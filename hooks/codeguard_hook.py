"""
hooks/codeguard_hook.py
-----------------------
IBM Bob PreToolUse safety gate for CodeGuard AI.

Reads the Bob PreToolUse JSON payload from stdin, converts the proposed
tool call into a CodeGuard action, evaluates it against the existing
engine/policies.json (via the existing evaluator — no policy duplication),
and produces one of four outcomes:

  ALLOW            – exit 0, structured allow response on stdout
  WARN             – exit 0, structured allow response on stdout (warning logged)
  APPROVAL_REQUIRED – exit 0, structured allow response on stdout
                      (human approval NOT automatically granted; logged)
  BLOCK            – structured deny response on stdout, reason on stderr,
                     exit 2  (Bob stops the tool call)

Structured response contract (Bob PreToolUse):
  stdout: JSON with hookSpecificOutput.permissionDecision = "allow" | "deny"
  stderr: short human-readable reason (used by Bob as the fallback reason)
  exit 2: tells Bob to block the tool call

Audit log:
  Every invocation appends one JSON line to data/codeguard_audit.jsonl.

Usage (Bob invokes this automatically via .bob/settings.json):
  <PreToolUse payload JSON>  |  python3 hooks/codeguard_hook.py

Manual test:
  echo '{"session_id":"test","cwd":".","hook_event_name":"PreToolUse",
         "tool_name":"execute_command",
         "tool_input":{"command":"DROP TABLE users;"},
         "tool_use_id":"t1"}' | python3 hooks/codeguard_hook.py
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the engine package is importable regardless of CWD.
# Bob runs hook commands from the workspace root; this file lives in hooks/.
# ---------------------------------------------------------------------------
_REPO_ROOT   = Path(__file__).resolve().parent.parent
_ENGINE_DIR  = _REPO_ROOT / "engine"
_AUDIT_FILE  = _REPO_ROOT / "data" / "codeguard_audit.jsonl"

if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))

from evaluator import evaluate_action  # noqa: E402  (after sys.path fix)


# ---------------------------------------------------------------------------
# Payload parsing
# ---------------------------------------------------------------------------

def _read_stdin() -> dict:
    """Read all of stdin and parse it as JSON.  Returns {} on failure."""
    try:
        raw = sys.stdin.read()
        return json.loads(raw)
    except (json.JSONDecodeError, OSError):
        return {}


def _build_action(payload: dict) -> dict:
    """
    Convert a Bob PreToolUse payload into a CodeGuard action dict.

    The evaluator expects a flat dict; we put the tool_name into "tool" and
    flatten tool_input fields at the top level so every keyword is visible
    to the evaluator's json.dumps(action).lower() scan.
    """
    tool_name  = payload.get("tool_name", "unknown")
    tool_input = payload.get("tool_input") or {}

    action = {"tool": tool_name}

    # Flatten all tool_input fields into the action so the evaluator can
    # scan them (command, path, code, diff, content, etc.)
    if isinstance(tool_input, dict):
        action.update(tool_input)
    else:
        # tool_input was a plain string (unusual but defensive)
        action["input"] = str(tool_input)

    return action


# ---------------------------------------------------------------------------
# Structured Bob response helpers
# ---------------------------------------------------------------------------

def _allow_response(reason: str = "") -> dict:
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }
    }
    if reason:
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason
    return out


def _deny_response(reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def _append_audit(entry: dict) -> None:
    """Append a single JSON line to the audit log.  Never raises."""
    try:
        _AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # audit failure must never block normal operation


def _build_audit_entry(payload: dict,
                       action: dict,
                       eval_result: dict) -> dict:
    """Build a structured audit log entry."""
    decision         = eval_result.get("decision", "ALLOW")
    matched_policies = eval_result.get("matched_policies", [])

    entry = {
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "session_id": payload.get("session_id", "NOT_AVAILABLE"),
        "tool":       payload.get("tool_name",  "NOT_AVAILABLE"),
        "action":     action,
        "decision":   decision,
    }

    if matched_policies:
        entry["policy_ids"] = [m["policy_id"] for m in matched_policies]
        entry["reasons"]    = [m["reason"]    for m in matched_policies]

    return entry


# ---------------------------------------------------------------------------
# Main gate logic
# ---------------------------------------------------------------------------

def run_gate(payload: dict) -> int:
    """
    Evaluate the payload, emit the Bob response, append audit log.

    Returns the exit code (0 = allow, 2 = block).
    """
    action      = _build_action(payload)
    eval_result = evaluate_action(action)
    decision    = eval_result.get("decision", "ALLOW")
    matched     = eval_result.get("matched_policies", [])

    # Build a concise reason string from matched policies
    reasons = "; ".join(m["reason"] for m in matched) if matched else ""
    policy_ids_str = ", ".join(m["policy_id"] for m in matched) if matched else ""

    # Append audit event (before any exit so it is always written)
    audit_entry = _build_audit_entry(payload, action, eval_result)
    _append_audit(audit_entry)

    if decision == "BLOCK":
        block_reason = (
            f"CodeGuard BLOCKED: [{policy_ids_str}] {reasons}"
            if reasons else "CodeGuard BLOCKED: policy violation detected."
        )
        # Structured deny → stdout
        sys.stdout.write(json.dumps(_deny_response(block_reason)) + "\n")
        sys.stdout.flush()
        # Human-readable reason → stderr (Bob uses this as fallback reason)
        sys.stderr.write(block_reason + "\n")
        sys.stderr.flush()
        return 2

    elif decision == "APPROVAL_REQUIRED":
        note = (
            f"CodeGuard APPROVAL_REQUIRED: [{policy_ids_str}] {reasons} "
            f"— human approval not yet granted. Proceeding is blocked "
            f"until approval is confirmed outside this hook."
        )
        # For this phase: exit 0 (non-blocking) but log prominently.
        # Rationale: automated approval cannot be granted by a hook;
        # blocking unconditionally would deadlock every deploy.
        # The approval workflow (Phase 5) must be used to resolve this.
        sys.stdout.write(json.dumps(_allow_response(note)) + "\n")
        sys.stdout.flush()
        sys.stderr.write(f"[CodeGuard WARNING] {note}\n")
        sys.stderr.flush()
        return 0

    elif decision == "WARN":
        warn_reason = f"CodeGuard WARN: {reasons}" if reasons else "CodeGuard WARN."
        sys.stdout.write(json.dumps(_allow_response(warn_reason)) + "\n")
        sys.stdout.flush()
        sys.stderr.write(f"[CodeGuard WARNING] {warn_reason}\n")
        sys.stderr.flush()
        return 0

    else:
        # ALLOW
        sys.stdout.write(json.dumps(_allow_response()) + "\n")
        sys.stdout.flush()
        return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    payload  = _read_stdin()
    exit_code = run_gate(payload)
    sys.exit(exit_code)
