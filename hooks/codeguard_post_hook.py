"""
hooks/codeguard_post_hook.py
-----------------------------
IBM Bob PostToolUse completion logger for CodeGuard AI.

Records that an allowed tool actually completed execution.
This hook is strictly for audit logging — it NEVER blocks.
(PostToolUse cannot block; exit 2 is ignored by Bob.)

Appends a single JSON line to data/codeguard_audit.jsonl with:
  - timestamp
  - session_id
  - tool name
  - hook_event = "PostToolUse"
  - completed = true

Usage (Bob invokes this automatically via .bob/settings.json):
  <PostToolUse payload JSON>  |  python3 hooks/codeguard_post_hook.py
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT  = Path(__file__).resolve().parent.parent
_AUDIT_FILE = _REPO_ROOT / "data" / "codeguard_audit.jsonl"


def _append_audit(entry: dict) -> None:
    """Append a single JSON line to the audit log.  Never raises."""
    try:
        _AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


if __name__ == "__main__":
    try:
        raw     = sys.stdin.read()
        payload = json.loads(raw)
    except (json.JSONDecodeError, OSError):
        payload = {}

    entry = {
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "hook_event":  "PostToolUse",
        "session_id":  payload.get("session_id", "NOT_AVAILABLE"),
        "tool":        payload.get("tool_name",  "NOT_AVAILABLE"),
        "completed":   True,
    }
    _append_audit(entry)
    # Always exit 0 — PostToolUse cannot block.
    sys.exit(0)
