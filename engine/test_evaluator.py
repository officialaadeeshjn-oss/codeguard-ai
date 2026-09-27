"""
Automated tests for the CodeGuard AI decision engine (engine/evaluator.py).

Each test submits a proposed tool action and asserts the expected final
decision and matched policy IDs.  Run with:

    python -m pytest engine/test_evaluator.py -v
  or
    python engine/test_evaluator.py
"""

import sys
import os

# Make sure the engine package is importable when run directly.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evaluator import evaluate_action  # noqa: E402


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def matched_ids(result):
    """Return the set of policy IDs that were matched in a result dict."""
    return {r["policy_id"] for r in result["matched_policies"]}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_safe_action_allow():
    """A harmless read action should be ALLOW with no matched policies."""
    action = {
        "tool": "read_file",
        "file_path": "src/utils.py",
    }
    result = evaluate_action(action)
    assert result["decision"] == "ALLOW", (
        f"Expected ALLOW but got {result['decision']}"
    )
    assert result["matched_policies"] == [], (
        f"Expected no matched policies but got {result['matched_policies']}"
    )
    print("PASS  test_safe_action_allow")


def test_drop_table_block_data001():
    """DROP TABLE users must be BLOCK and match DATA-001."""
    action = {
        "tool": "terminal",
        "command": "DROP TABLE users;",
    }
    result = evaluate_action(action)
    assert result["decision"] == "BLOCK", (
        f"Expected BLOCK but got {result['decision']}"
    )
    assert "DATA-001" in matched_ids(result), (
        f"Expected DATA-001 in matched policies but got {matched_ids(result)}"
    )
    print("PASS  test_drop_table_block_data001")


def test_authentication_bypass_block_auth001():
    """An action that disables auth must be BLOCK and match AUTH-001."""
    action = {
        "tool": "edit_file",
        "code": "// bypass authentication for internal routes",
    }
    result = evaluate_action(action)
    assert result["decision"] == "BLOCK", (
        f"Expected BLOCK but got {result['decision']}"
    )
    assert "AUTH-001" in matched_ids(result), (
        f"Expected AUTH-001 in matched policies but got {matched_ids(result)}"
    )
    print("PASS  test_authentication_bypass_block_auth001")


def test_plaintext_reset_token_block_auth002():
    """Storing a reset token in plaintext must be BLOCK and match AUTH-002."""
    action = {
        "tool": "edit_file",
        "code": "db.save(reset_token, plaintext)",
        "command": "store reset token plaintext in database",
    }
    result = evaluate_action(action)
    assert result["decision"] == "BLOCK", (
        f"Expected BLOCK but got {result['decision']}"
    )
    assert "AUTH-002" in matched_ids(result), (
        f"Expected AUTH-002 in matched policies but got {matched_ids(result)}"
    )
    print("PASS  test_plaintext_reset_token_block_auth002")


def test_production_deployment_approval_required():
    """A production deployment must be APPROVAL_REQUIRED and match DEPLOY-001."""
    action = {
        "tool": "terminal",
        "command": "deploy to production",
    }
    result = evaluate_action(action)
    assert result["decision"] == "APPROVAL_REQUIRED", (
        f"Expected APPROVAL_REQUIRED but got {result['decision']}"
    )
    assert "DEPLOY-001" in matched_ids(result), (
        f"Expected DEPLOY-001 in matched policies but got {matched_ids(result)}"
    )
    print("PASS  test_production_deployment_approval_required")


def test_force_push_main_block_git001():
    """Force-pushing to main must be BLOCK and match GIT-001."""
    action = {
        "tool": "terminal",
        "command": "git push origin main --force",
    }
    result = evaluate_action(action)
    assert result["decision"] == "BLOCK", (
        f"Expected BLOCK but got {result['decision']}"
    )
    assert "GIT-001" in matched_ids(result), (
        f"Expected GIT-001 in matched policies but got {matched_ids(result)}"
    )
    print("PASS  test_force_push_main_block_git001")


def test_hardcoded_secret_block_sec001():
    """A hardcoded API key must be BLOCK and match SEC-001."""
    action = {
        "tool": "edit_file",
        "code": 'api_key = "sk-abc123supersecret"',
    }
    result = evaluate_action(action)
    assert result["decision"] == "BLOCK", (
        f"Expected BLOCK but got {result['decision']}"
    )
    assert "SEC-001" in matched_ids(result), (
        f"Expected SEC-001 in matched policies but got {matched_ids(result)}"
    )
    print("PASS  test_hardcoded_secret_block_sec001")


# ---------------------------------------------------------------------------
# Runner (when executed directly with `python engine/test_evaluator.py`)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_safe_action_allow,
        test_drop_table_block_data001,
        test_authentication_bypass_block_auth001,
        test_plaintext_reset_token_block_auth002,
        test_production_deployment_approval_required,
        test_force_push_main_block_git001,
        test_hardcoded_secret_block_sec001,
    ]

    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {t.__name__}: {e}")
            failed += 1

    print(f"\n{passed + failed} tests | {passed} passed | {failed} failed")
    sys.exit(0 if failed == 0 else 1)
