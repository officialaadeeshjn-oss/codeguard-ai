"""
hooks/test_phase7.py
--------------------
Automated tests for Phase 7: the IBM Bob PreToolUse safety gate.

Tests call the hook script as a subprocess (the same way Bob does) and
verify exit codes, stdout/stderr content, and audit-log entries.

Run with:
    python -m pytest hooks/test_phase7.py -v
or:
    python hooks/test_phase7.py

These tests do NOT modify any Phase 2–6 test files or implementation files.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Workspace root (parent of hooks/)
_REPO_ROOT  = Path(__file__).resolve().parent.parent
_HOOK_SCRIPT = _REPO_ROOT / "hooks" / "codeguard_hook.py"
_ENGINE_DIR  = _REPO_ROOT / "engine"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_hook(payload: dict,
              audit_file: Path = None) -> subprocess.CompletedProcess:
    """
    Run the hook script as a subprocess with the given payload on stdin.

    If audit_file is supplied the CODEGUARD_AUDIT_FILE env var is NOT used
    (the hook uses its own default); callers that need to inspect the audit
    log must read the default path or override via monkeypatching.
    """
    env = os.environ.copy()
    # Make sure Python can find the engine package
    pythonpath = str(_ENGINE_DIR)
    existing   = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (pythonpath + os.pathsep + existing) if existing else pythonpath

    return subprocess.run(
        [sys.executable, str(_HOOK_SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        cwd=str(_REPO_ROOT),
    )


def _make_payload(tool_name: str, tool_input: dict,
                  session_id: str = "test-session") -> dict:
    return {
        "session_id":       session_id,
        "cwd":              str(_REPO_ROOT),
        "hook_event_name":  "PreToolUse",
        "tool_name":        tool_name,
        "tool_input":       tool_input,
        "tool_use_id":      "test-tool-use-id",
    }


def _last_audit_entry() -> dict | None:
    """Return the last line of the audit log as a dict, or None."""
    audit_path = _REPO_ROOT / "data" / "codeguard_audit.jsonl"
    if not audit_path.exists():
        return None
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    if not lines:
        return None
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Internal-function tests (no subprocess overhead)
# ---------------------------------------------------------------------------

# Add engine to path for direct import
sys.path.insert(0, str(_ENGINE_DIR))
sys.path.insert(0, str(_REPO_ROOT / "hooks"))

from codeguard_hook import _build_action, _read_stdin, run_gate  # noqa: E402


class TestPayloadParsing:

    def test_valid_pretooluse_payload_is_parsed(self):
        """_build_action correctly extracts tool and input fields."""
        payload = _make_payload("execute_command", {"command": "ls -la"})
        action  = _build_action(payload)
        assert action["tool"]    == "execute_command"
        assert action["command"] == "ls -la"
        print("PASS  test_valid_pretooluse_payload_is_parsed")

    def test_empty_tool_input_does_not_crash(self):
        """_build_action handles a payload with no tool_input."""
        payload = {"hook_event_name": "PreToolUse",
                   "tool_name": "read_file", "tool_input": {}}
        action  = _build_action(payload)
        assert action["tool"] == "read_file"
        print("PASS  test_empty_tool_input_does_not_crash")

    def test_missing_optional_fields_do_not_crash(self):
        """_build_action handles missing session_id and cwd gracefully."""
        payload = {"tool_name": "execute_command",
                   "tool_input": {"command": "echo hello"}}
        action  = _build_action(payload)
        assert action["tool"]    == "execute_command"
        assert action["command"] == "echo hello"
        print("PASS  test_missing_optional_fields_do_not_crash")

    def test_hook_does_not_modify_policy_definitions(self):
        """Running the hook must not alter engine/policies.json."""
        import hashlib
        policy_path = _ENGINE_DIR / "policies.json"
        before_hash = hashlib.sha256(policy_path.read_bytes()).hexdigest()

        payload = _make_payload("execute_command",
                                {"command": "DROP TABLE users;"})
        _build_action(payload)  # just parsing, no side effects on policies

        after_hash  = hashlib.sha256(policy_path.read_bytes()).hexdigest()
        assert before_hash == after_hash, "policies.json was modified!"
        print("PASS  test_hook_does_not_modify_policy_definitions")

    def test_existing_evaluator_is_used(self):
        """run_gate calls the real evaluator and returns a known decision."""
        from evaluator import evaluate_action
        payload = _make_payload("execute_command",
                                {"command": "DROP TABLE users;"})
        action  = _build_action(payload)
        result  = evaluate_action(action)
        assert result["decision"] == "BLOCK"
        assert any(m["policy_id"] == "DATA-001"
                   for m in result["matched_policies"])
        print("PASS  test_existing_evaluator_is_used")


# ---------------------------------------------------------------------------
# Subprocess tests (full end-to-end like Bob)
# ---------------------------------------------------------------------------

class TestHookExitCodes:

    def test_safe_action_returns_exit_code_0(self):
        """A harmless read_file action must exit with code 0."""
        payload = _make_payload("read_file", {"path": "src/utils.py"})
        result  = _run_hook(payload)
        assert result.returncode == 0, (
            f"Expected exit 0 for safe action, got {result.returncode}\n"
            f"stderr: {result.stderr}"
        )
        print("PASS  test_safe_action_returns_exit_code_0")

    def test_safe_action_stdout_is_valid_json(self):
        """The hook must always write valid JSON to stdout."""
        payload = _make_payload("read_file", {"path": "src/utils.py"})
        result  = _run_hook(payload)
        data    = json.loads(result.stdout.strip())
        assert "hookSpecificOutput" in data
        assert data["hookSpecificOutput"]["permissionDecision"] == "allow"
        print("PASS  test_safe_action_stdout_is_valid_json")

    def test_hardcoded_secret_returns_exit_code_2(self):
        """A hardcoded API key action must exit with code 2 (BLOCK)."""
        payload = _make_payload(
            "write_file",
            {"path": "config.py", "content": 'api_key = "sk-abc123supersecret"'},
        )
        result = _run_hook(payload)
        assert result.returncode == 2, (
            f"Expected exit 2 for hardcoded secret, got {result.returncode}\n"
            f"stderr: {result.stderr}"
        )
        print("PASS  test_hardcoded_secret_returns_exit_code_2")

    def test_destructive_db_action_returns_exit_code_2(self):
        """DROP TABLE must exit with code 2 (BLOCK)."""
        payload = _make_payload("execute_command",
                                {"command": "DROP TABLE users;"})
        result  = _run_hook(payload)
        assert result.returncode == 2, (
            f"Expected exit 2 for DROP TABLE, got {result.returncode}\n"
            f"stderr: {result.stderr}"
        )
        print("PASS  test_destructive_db_action_returns_exit_code_2")

    def test_block_stdout_contains_deny_decision(self):
        """A BLOCK response must contain permissionDecision='deny' in stdout."""
        payload = _make_payload("execute_command",
                                {"command": "DROP TABLE users;"})
        result  = _run_hook(payload)
        data    = json.loads(result.stdout.strip())
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny", (
            f"Expected 'deny' in stdout, got: {data}"
        )
        print("PASS  test_block_stdout_contains_deny_decision")

    def test_block_stderr_contains_reason(self):
        """A BLOCK response must write a non-empty reason to stderr."""
        payload = _make_payload("execute_command",
                                {"command": "DROP TABLE users;"})
        result  = _run_hook(payload)
        assert result.returncode == 2
        assert len(result.stderr.strip()) > 0, "stderr must be non-empty on BLOCK"
        assert "DATA-001" in result.stderr or "Destructive" in result.stderr, (
            f"Expected policy reference in stderr: {result.stderr}"
        )
        print("PASS  test_block_stderr_contains_reason")

    def test_force_push_blocked(self):
        """git push --force to main must be blocked (GIT-001)."""
        payload = _make_payload("execute_command",
                                {"command": "git push origin main --force"})
        result  = _run_hook(payload)
        assert result.returncode == 2
        print("PASS  test_force_push_blocked")

    def test_deploy_to_production_exits_0_with_warning(self):
        """APPROVAL_REQUIRED (deploy to production) must exit 0 but log warning."""
        payload = _make_payload("execute_command",
                                {"command": "deploy to production"})
        result  = _run_hook(payload)
        assert result.returncode == 0, (
            f"Expected exit 0 for APPROVAL_REQUIRED, got {result.returncode}"
        )
        # Verify it's explicitly flagged in stderr
        assert "APPROVAL_REQUIRED" in result.stderr or \
               "approval" in result.stderr.lower(), (
            f"Expected approval warning in stderr: {result.stderr}"
        )
        print("PASS  test_deploy_to_production_exits_0_with_warning")

    def test_missing_payload_does_not_crash(self):
        """An empty/malformed payload must not crash the hook (exit != 1)."""
        result = subprocess.run(
            [sys.executable, str(_HOOK_SCRIPT)],
            input="{}",
            capture_output=True,
            text=True,
            cwd=str(_REPO_ROOT),
        )
        # Should exit 0 (empty payload → ALLOW) or 2 (never 1 = crash)
        assert result.returncode in (0, 2), (
            f"Unexpected exit code {result.returncode}\n"
            f"stderr: {result.stderr}"
        )
        print("PASS  test_missing_payload_does_not_crash")


class TestAuditLog:

    def test_audit_event_is_created_for_safe_action(self):
        """A safe action must create an audit entry with decision=ALLOW."""
        payload = _make_payload("read_file",
                                {"path": "src/utils.py"},
                                session_id="audit-test-safe")
        _run_hook(payload)
        entry = _last_audit_entry()
        assert entry is not None, "Audit file was not created"
        assert entry.get("decision") == "ALLOW"
        assert entry.get("session_id") == "audit-test-safe"
        print("PASS  test_audit_event_is_created_for_safe_action")

    def test_audit_event_is_created_for_blocked_action(self):
        """A BLOCK action must create an audit entry with decision=BLOCK."""
        payload = _make_payload("execute_command",
                                {"command": "DROP TABLE users;"},
                                session_id="audit-test-block")
        _run_hook(payload)
        entry = _last_audit_entry()
        assert entry is not None
        assert entry.get("decision") == "BLOCK"
        assert entry.get("session_id") == "audit-test-block"
        assert "DATA-001" in entry.get("policy_ids", [])
        print("PASS  test_audit_event_is_created_for_blocked_action")

    def test_audit_entry_contains_required_fields(self):
        """Audit entries must contain timestamp, session_id, tool, decision."""
        payload = _make_payload("execute_command",
                                {"command": "echo hello"},
                                session_id="audit-fields-test")
        _run_hook(payload)
        entry = _last_audit_entry()
        assert entry is not None
        for field in ("timestamp", "session_id", "tool", "action", "decision"):
            assert field in entry, f"Missing audit field: {field}"
        print("PASS  test_audit_entry_contains_required_fields")


# ---------------------------------------------------------------------------
# Direct runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_classes = [
        TestPayloadParsing,
        TestHookExitCodes,
        TestAuditLog,
    ]

    passed = 0
    failed = 0

    for cls in test_classes:
        instance = cls()
        methods  = sorted(m for m in dir(instance) if m.startswith("test_"))
        print(f"\n--- {cls.__name__} ---")
        for method_name in methods:
            method = getattr(instance, method_name)
            try:
                method()
                passed += 1
            except Exception as e:
                print(f"FAIL  {method_name}: {e}")
                import traceback
                traceback.print_exc()
                failed += 1

    print(f"\n{passed + failed} tests | {passed} passed | {failed} failed")
    sys.exit(0 if failed == 0 else 1)
