"""
engine/attack_tests.py
----------------------
Lightweight deterministic attack-path / security test-case generator
for CodeGuard AI.

For a proposed action and its CodeGuard decision, this module produces a
list of structured security test cases that SHOULD be executed before the
action (or a safer alternative) is allowed to proceed.

Design principles
-----------------
- Deterministic: same input → same test cases.
- Honest: generated tests are DESCRIPTIONS, not executed assertions.
  The test_gate module is responsible for tracking actual results.
- Policy-driven: each policy has a set of attack-path tests tailored to
  the threat it guards against.
- Each test case carries a unique ID so the test_gate can reference it.

Usage:
    from engine.evaluator import evaluate_action
    from engine.attack_tests import generate_attack_tests

    action = {"tool": "edit_file",
              "command": "store reset token plaintext in database"}
    eval_result = evaluate_action(action)
    tests = generate_attack_tests(action, eval_result)
"""

# ---------------------------------------------------------------------------
# Per-policy attack-path test templates
# Each entry is a list of test-case dicts:
#   id          – stable short identifier (policy-prefix + number)
#   name        – human-readable test name
#   description – what the test checks and what the expected outcome is
#   category    – attack category (e.g. "authentication", "data integrity")
# ---------------------------------------------------------------------------

_POLICY_TESTS = {
    "SEC-001": [
        {
            "id": "SEC-001-T1",
            "name": "Hardcoded credential must not appear in source",
            "description": (
                "Scan the modified file(s) for patterns matching known "
                "credential formats (API keys, tokens, passwords). "
                "Expected: zero findings."
            ),
            "category": "secret_exposure",
        },
        {
            "id": "SEC-001-T2",
            "name": "Secret must be loaded from environment at runtime",
            "description": (
                "Verify the application reads the credential from an "
                "environment variable or secrets manager, not a literal. "
                "Expected: credential value absent from source; present at runtime."
            ),
            "category": "secret_exposure",
        },
        {
            "id": "SEC-001-T3",
            "name": "Exposed credential must be rotated",
            "description": (
                "If the credential was ever committed to VCS history, confirm "
                "it has been revoked and replaced. "
                "Expected: old credential is invalid."
            ),
            "category": "credential_rotation",
        },
    ],
    "AUTH-001": [
        {
            "id": "AUTH-001-T1",
            "name": "Unauthenticated request to protected endpoint must be rejected",
            "description": (
                "Send a request to a protected endpoint without any "
                "authentication token. "
                "Expected: HTTP 401 Unauthorized."
            ),
            "category": "authentication",
        },
        {
            "id": "AUTH-001-T2",
            "name": "Invalid token must be rejected",
            "description": (
                "Send a request with a malformed or expired JWT/session token. "
                "Expected: HTTP 401 or 403."
            ),
            "category": "authentication",
        },
        {
            "id": "AUTH-001-T3",
            "name": "Privilege escalation attempt must fail",
            "description": (
                "Attempt to access an admin-only endpoint with a regular-user "
                "token. "
                "Expected: HTTP 403 Forbidden."
            ),
            "category": "authorization",
        },
        {
            "id": "AUTH-001-T4",
            "name": "All previously protected routes must still require auth",
            "description": (
                "After the change, iterate over every previously protected "
                "route and confirm each still returns 401 without credentials. "
                "Expected: no route has become accidentally public."
            ),
            "category": "authentication",
        },
    ],
    "AUTH-002": [
        {
            "id": "AUTH-002-T1",
            "name": "Expired OTP/reset token must be rejected",
            "description": (
                "Submit a valid-format reset token after its expiration window "
                "has passed. "
                "Expected: token rejected with an appropriate error."
            ),
            "category": "otp_reset",
        },
        {
            "id": "AUTH-002-T2",
            "name": "Incorrect OTP/reset token must be rejected",
            "description": (
                "Submit a randomly generated token that was never issued. "
                "Expected: token rejected; account not reset."
            ),
            "category": "otp_reset",
        },
        {
            "id": "AUTH-002-T3",
            "name": "Reused OTP/reset token must be rejected",
            "description": (
                "Use a valid token to perform a reset, then attempt to use the "
                "same token a second time. "
                "Expected: second use is rejected (token invalidated after first use)."
            ),
            "category": "otp_reset",
        },
        {
            "id": "AUTH-002-T4",
            "name": "Unauthorised reset attempt must fail",
            "description": (
                "Attempt to reset the password for account B using a token "
                "issued to account A. "
                "Expected: request rejected; account B unchanged."
            ),
            "category": "otp_reset",
        },
        {
            "id": "AUTH-002-T5",
            "name": "Reset token must not be stored in plaintext",
            "description": (
                "Inspect the database record created during a reset flow. "
                "Expected: the stored value is a hash, not the raw token."
            ),
            "category": "otp_reset",
        },
        {
            "id": "AUTH-002-T6",
            "name": "Reset token must not appear in logs or API responses",
            "description": (
                "Trigger a reset flow and inspect application logs and all "
                "API response bodies. "
                "Expected: raw token value absent from logs and responses "
                "beyond the initial issuance message."
            ),
            "category": "otp_reset",
        },
    ],
    "DATA-001": [
        {
            "id": "DATA-001-T1",
            "name": "Destructive operation must be blocked in production",
            "description": (
                "Attempt to execute the destructive SQL statement against the "
                "production database without the required approval. "
                "Expected: operation is blocked by CodeGuard."
            ),
            "category": "data_integrity",
        },
        {
            "id": "DATA-001-T2",
            "name": "Protected data must remain intact after operation",
            "description": (
                "After any permitted migration, verify that related tables and "
                "foreign-key constraints are intact. "
                "Expected: no unintended data loss."
            ),
            "category": "data_integrity",
        },
        {
            "id": "DATA-001-T3",
            "name": "Database backup must exist and be restorable",
            "description": (
                "Confirm a current backup exists and perform a test restore to "
                "a staging database before the operation proceeds. "
                "Expected: restore succeeds within the recovery-time objective."
            ),
            "category": "data_integrity",
        },
    ],
    "GIT-001": [
        {
            "id": "GIT-001-T1",
            "name": "Force-push to protected branch must be rejected",
            "description": (
                "Attempt git push --force on main/master. "
                "Expected: push is rejected by branch-protection rules."
            ),
            "category": "source_control",
        },
        {
            "id": "GIT-001-T2",
            "name": "No commits lost after merge operation",
            "description": (
                "After a legitimate merge into main, confirm no commits from "
                "other contributors are missing. "
                "Expected: git log shows all expected commits."
            ),
            "category": "source_control",
        },
        {
            "id": "GIT-001-T3",
            "name": "CI pipeline remains intact after branch operation",
            "description": (
                "Confirm the CI pipeline is still referencing valid commit "
                "SHAs after the branch operation. "
                "Expected: CI passes on the current HEAD."
            ),
            "category": "source_control",
        },
    ],
    "DEPLOY-001": [
        {
            "id": "DEPLOY-001-T1",
            "name": "Deployment without approval must be blocked",
            "description": (
                "Attempt to trigger a production deployment without going "
                "through the CodeGuard approval workflow. "
                "Expected: deployment is blocked."
            ),
            "category": "deployment",
        },
        {
            "id": "DEPLOY-001-T2",
            "name": "Smoke tests must pass post-deployment",
            "description": (
                "After a production deployment (with approval), run the smoke "
                "test suite against the live environment. "
                "Expected: all smoke tests pass."
            ),
            "category": "deployment",
        },
        {
            "id": "DEPLOY-001-T3",
            "name": "Rollback procedure must work",
            "description": (
                "Verify that the documented rollback procedure restores the "
                "previous version successfully. "
                "Expected: rollback completes without errors."
            ),
            "category": "deployment",
        },
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_attack_tests(action: dict, eval_result: dict) -> dict:
    """
    Generate a set of security test cases for a proposed action.

    Parameters
    ----------
    action      : the raw action dict passed to evaluate_action
    eval_result : the dict returned by evaluate_action

    Returns
    -------
    dict with keys:
        matched_policy_ids  – list of policy IDs that triggered
        test_cases          – list of test-case dicts, each containing:
                                id, name, description, category, policy_id
        total               – total number of test cases generated
        disclaimer          – honest note about execution status
    """
    matched_policies = eval_result.get("matched_policies", [])
    matched_ids      = [m["policy_id"] for m in matched_policies]

    test_cases = []
    seen       = set()  # avoid duplicate IDs if a policy appears twice

    for pid in matched_ids:
        if pid in seen:
            continue
        seen.add(pid)
        for tc in _POLICY_TESTS.get(pid, []):
            # Attach the originating policy ID to each test case
            test_cases.append(dict(tc, policy_id=pid))

    return {
        "matched_policy_ids": matched_ids,
        "test_cases":         test_cases,
        "total":              len(test_cases),
        "disclaimer": (
            "These are GENERATED test descriptions. "
            "They have NOT been executed. "
            "Use the test_gate module to record and evaluate actual results."
        ),
    }


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from evaluator import evaluate_action

    action = {
        "tool": "edit_file",
        "command": "store reset token plaintext in database",
    }
    result = evaluate_action(action)
    tests = generate_attack_tests(action, result)
    print(json.dumps(tests, indent=2))
