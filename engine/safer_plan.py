"""
engine/safer_plan.py
--------------------
Safer-plan generator for CodeGuard AI.

When the policy evaluator blocks or flags an action, this module produces a
structured safer implementation plan: what was wrong, why, and concrete
alternative steps the agent should take instead.

Design principles
-----------------
- Deterministic: same input → same plan.
- Honest: does NOT claim the safer plan was executed or verified.
- Policy-driven: each of the six policies has its own safer-steps template.
- Additive: accepts the action, eval_result, and optional evidence dict
  so downstream callers can pass in whatever they already have.

Usage:
    from engine.evaluator import evaluate_action
    from engine.safer_plan import generate_safer_plan

    action = {
        "tool": "edit_file",
        "command": "store reset token plaintext in database",
    }
    eval_result = evaluate_action(action)
    plan = generate_safer_plan(action, eval_result)
"""

# ---------------------------------------------------------------------------
# Per-policy safer-step templates
# Each entry maps policy ID → dict with:
#   why_unsafe       – one-sentence explanation of the risk
#   safer_steps      – ordered list of concrete alternative steps
#   verification     – what must be checked before the action can proceed
# ---------------------------------------------------------------------------

_POLICY_PLANS = {
    "SEC-001": {
        "why_unsafe": (
            "Hardcoded credentials (API keys, passwords, tokens, secrets) "
            "embedded in source code are visible to anyone with repository "
            "access and are frequently leaked via version-control history."
        ),
        "safer_steps": [
            "Remove the hardcoded value from the source file.",
            "Store the secret in an environment variable or a secrets manager "
            "(e.g. AWS Secrets Manager, HashiCorp Vault, .env file excluded from VCS).",
            "Read the value at runtime via os.environ or a secrets-client library.",
            "Rotate the exposed credential immediately if it was ever committed.",
            "Add a pre-commit hook or CI check (e.g. gitleaks, truffleHog) to "
            "prevent future hardcoded secrets.",
        ],
        "verification": [
            "Confirm the secret no longer appears anywhere in the diff.",
            "Confirm the environment variable is documented in .env.example "
            "(without the real value).",
            "Run the secret-scanning check and confirm zero findings.",
        ],
    },
    "AUTH-001": {
        "why_unsafe": (
            "Disabling or bypassing authentication removes the security boundary "
            "that protects all resources behind it, potentially exposing every "
            "authenticated endpoint to unauthenticated access."
        ),
        "safer_steps": [
            "Do not remove or comment out the authentication middleware.",
            "If a specific route must be public, explicitly whitelist only that "
            "route in the middleware configuration rather than disabling auth globally.",
            "Add an integration test that asserts protected endpoints return 401 "
            "when called without a valid token.",
            "Document the reason a route is public and require a second reviewer "
            "to approve any auth-boundary change.",
        ],
        "verification": [
            "Confirm all previously protected endpoints still require a valid token.",
            "Run the authentication test suite and confirm it passes.",
            "Confirm no route is accidentally left unprotected.",
        ],
    },
    "AUTH-002": {
        "why_unsafe": (
            "Storing a password-reset or OTP token in plaintext means anyone "
            "with database read access (or who obtains a database dump) can use "
            "the token to take over any account without knowing the password."
        ),
        "safer_steps": [
            "Generate the OTP/reset token using a cryptographically secure "
            "random source (e.g. secrets.token_urlsafe(32) in Python).",
            "Store only a secure hash of the token in the database "
            "(e.g. hashlib.sha256(token.encode()).hexdigest()).",
            "Set a short expiration time on the token (e.g. 15 minutes).",
            "Invalidate the token immediately after it has been used once.",
            "Never log or return the raw token value in an API response body "
            "beyond the initial issuance.",
            "Send the raw token to the user only via a trusted out-of-band "
            "channel (email, SMS) — never embed it in a URL that may be cached.",
        ],
        "verification": [
            "Confirm the database column stores only the hashed value.",
            "Confirm the token expires correctly by testing with an expired token.",
            "Confirm a reused token is rejected after first use.",
            "Confirm an incorrect token is rejected.",
            "Run the password-reset / OTP test suite.",
        ],
    },
    "DATA-001": {
        "why_unsafe": (
            "Destructive database operations (DROP TABLE, DROP DATABASE, "
            "DELETE without a WHERE clause, TRUNCATE) permanently destroy data "
            "and are irreversible without a backup."
        ),
        "safer_steps": [
            "Take a verified database backup before any schema or bulk-delete operation.",
            "Replace DROP/TRUNCATE with a soft-delete approach "
            "(e.g. add an 'is_deleted' flag) unless permanent removal is explicitly required.",
            "If permanent deletion is required, add a WHERE clause scoping the "
            "operation to only the intended rows.",
            "Run the operation in a transaction with an explicit ROLLBACK test "
            "on a staging database first.",
            "Require a second human reviewer to approve any migration that "
            "contains destructive SQL.",
        ],
        "verification": [
            "Confirm a current backup exists and has been tested for restore.",
            "Confirm the migration has been reviewed and approved.",
            "Confirm the staging environment ran successfully.",
            "Run the database integration tests after applying the migration.",
        ],
    },
    "GIT-001": {
        "why_unsafe": (
            "Force-pushing to a protected branch (main/master) rewrites "
            "shared history, can permanently discard other contributors' commits, "
            "and breaks any CI/CD pipeline that references those commit SHAs."
        ),
        "safer_steps": [
            "Do NOT use --force or --force-with-lease on protected branches.",
            "Instead, open a pull/merge request and resolve conflicts via a merge commit.",
            "If history must be cleaned up, do so on a feature branch only, "
            "never on main/master.",
            "Enable branch-protection rules on the hosting platform to reject "
            "force-pushes server-side.",
        ],
        "verification": [
            "Confirm branch-protection rules are enabled for main.",
            "Confirm the CI pipeline is still referencing valid commit SHAs.",
            "Confirm no commits have been lost by comparing the branch tip "
            "with the remote before and after.",
        ],
    },
    "DEPLOY-001": {
        "why_unsafe": (
            "Deploying directly to production without human approval risks "
            "introducing unreviewed changes, breaking live users, and making "
            "it difficult to audit what was deployed and by whom."
        ),
        "safer_steps": [
            "Submit the deployment for human approval through the CodeGuard "
            "approval workflow before proceeding.",
            "Ensure the deployment has passed all CI tests on the staging environment.",
            "Tag the release with a semantic version and update the changelog.",
            "Have a rollback plan ready (previous image tag, feature flag, etc.).",
            "Notify the on-call/team channel before and after the deployment.",
        ],
        "verification": [
            "Confirm the approval has been granted by an authorised reviewer.",
            "Confirm all staging tests passed.",
            "Confirm the rollback procedure is documented and has been tested.",
            "Run smoke tests against production immediately after deployment.",
        ],
    },
}

# Fallback for unrecognised policies
_DEFAULT_PLAN = {
    "why_unsafe": "This action was flagged by a CodeGuard policy.",
    "safer_steps": [
        "Review the flagged action carefully before proceeding.",
        "Consult the relevant policy documentation.",
        "Seek a second opinion if the risk is unclear.",
    ],
    "verification": [
        "Confirm the action does not violate the matched policy.",
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_safer_plan(action: dict,
                        eval_result: dict,
                        evidence: dict = None) -> dict:
    """
    Generate a structured safer implementation plan for a flagged action.

    Parameters
    ----------
    action      : the raw action dict passed to evaluate_action
    eval_result : the dict returned by evaluate_action
    evidence    : optional dict returned by extract_evidence (Phase 3)

    Returns
    -------
    dict with keys:
        original_action     – the action as submitted
        decision            – the final decision from the evaluator
        matched_policy_ids  – list of policy IDs that triggered
        why_unsafe          – explanation of why the action is unsafe
        safer_steps         – ordered list of recommended alternative steps
        affected_components – files / components likely impacted
        verification_steps  – what must be checked before the action proceeds
        disclaimer          – honest note about the scope of this plan
    """
    decision         = eval_result.get("decision", "ALLOW")
    matched_policies = eval_result.get("matched_policies", [])
    matched_ids      = [m["policy_id"] for m in matched_policies]

    # Collect why_unsafe and safer_steps from ALL matched policies
    # (an action may violate more than one policy simultaneously)
    why_parts   = []
    step_parts  = []
    verify_parts = []

    seen_policies = set()
    for m in matched_policies:
        pid = m["policy_id"]
        if pid in seen_policies:
            continue
        seen_policies.add(pid)
        template = _POLICY_PLANS.get(pid, _DEFAULT_PLAN)
        why_parts.append(f"[{pid}] {template['why_unsafe']}")
        step_parts.extend(template["safer_steps"])
        verify_parts.extend(template["verification"])

    if not why_parts:
        # ALLOW or no known policy — produce a minimal informational plan
        why_parts   = ["No policy was violated; this plan is informational only."]
        step_parts  = ["No corrective action required."]
        verify_parts = ["No verification required."]

    # Affected components: pull from evidence if provided, else from action
    affected = []
    if evidence:
        if evidence.get("affected_file"):
            affected.append(evidence["affected_file"])
        if evidence.get("api_component"):
            affected.append(evidence["api_component"])
        if evidence.get("db_component"):
            affected.append(evidence["db_component"])
    else:
        fp = action.get("file_path") or action.get("path")
        if fp:
            affected.append(fp)

    return {
        "original_action":     action,
        "decision":            decision,
        "matched_policy_ids":  matched_ids,
        "why_unsafe":          why_parts,
        "safer_steps":         step_parts,
        "affected_components": affected,
        "verification_steps":  verify_parts,
        "disclaimer": (
            "This safer plan is a deterministic heuristic guide. "
            "It does not guarantee security compliance. "
            "Human review is required before proceeding."
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
    plan = generate_safer_plan(action, result)
    print(json.dumps(plan, indent=2))
