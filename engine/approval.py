"""
engine/approval.py
------------------
Human-approval component for CodeGuard AI.

Manages approval records for actions flagged by the policy evaluator.

Decision → approval behaviour
------------------------------
  ALLOW            – no approval required; record is created with status
                     "not_required" and cannot be changed.
  WARN             – no mandatory approval; record is "not_required".
  BLOCK            – approval is permanently impossible; a BLOCK decision
                     means the action must not proceed regardless of who
                     requests approval.  Status is locked to "blocked".
  APPROVAL_REQUIRED – a pending approval record is created.  An authorised
                     caller may then approve or reject it.

Approval states for APPROVAL_REQUIRED
--------------------------------------
  pending   – created, waiting for a human decision
  approved  – a human approver accepted the action
  rejected  – a human approver rejected the action

Immutability rules
------------------
  - A "blocked" record can NEVER be changed to any other status.
  - A "not_required" record can NEVER be changed.
  - Once "approved" or "rejected", the record cannot be changed again
    (first human decision is final).

Timestamps
----------
  The component does NOT use real wall-clock time unless the caller
  supplies a timestamp explicitly.  This keeps the module deterministic
  and testable.  The timestamp field is a plain string; pass an ISO-8601
  string or any other label that is meaningful in your context.

Usage:
    from engine.approval import create_approval_record, decide_approval

    record = create_approval_record(
        action      = {"tool": "terminal", "command": "deploy to production"},
        eval_result = evaluate_action(action),
    )
    # record["status"] == "pending"

    updated = decide_approval(record, decision="approved",
                              approver="alice@example.com",
                              timestamp="2024-01-15T10:00:00Z")
    # updated["status"] == "approved"
"""

# Valid approval decisions a human can make
_HUMAN_DECISIONS = {"approved", "rejected"}

# Status values that can never be overwritten
_IMMUTABLE_STATUSES = {"blocked", "not_required", "approved", "rejected"}


def create_approval_record(action: dict, eval_result: dict) -> dict:
    """
    Create an approval record for a proposed action.

    Parameters
    ----------
    action      : the raw action dict passed to evaluate_action
    eval_result : the dict returned by evaluate_action

    Returns
    -------
    dict with keys:
        action          – the original action
        decision        – the evaluator's final decision
        policy_ids      – list of matched policy IDs (may be empty)
        reasons         – list of matched policy reasons (may be empty)
        status          – "pending" | "not_required" | "blocked"
        approver        – None (set when a human decides)
        timestamp       – None (set when a human decides)
        notes           – human-readable explanation of the current status
    """
    decision         = eval_result.get("decision", "ALLOW")
    matched_policies = eval_result.get("matched_policies", [])
    policy_ids       = [m["policy_id"] for m in matched_policies]
    reasons          = [m["reason"]    for m in matched_policies]

    if decision == "BLOCK":
        status = "blocked"
        notes  = (
            "This action is BLOCKED by policy and cannot be approved. "
            "A BLOCK decision is permanent — no approver can override it."
        )
    elif decision == "APPROVAL_REQUIRED":
        status = "pending"
        notes  = (
            "This action requires human approval before it can proceed. "
            "An authorised approver must call decide_approval()."
        )
    else:
        # ALLOW or WARN
        status = "not_required"
        notes  = (
            f"Decision is {decision}. No approval is required for this action."
        )

    return {
        "action":     action,
        "decision":   decision,
        "policy_ids": policy_ids,
        "reasons":    reasons,
        "status":     status,
        "approver":   None,
        "timestamp":  None,
        "notes":      notes,
    }


def decide_approval(record: dict,
                    decision: str,
                    approver: str,
                    timestamp: str = None) -> dict:
    """
    Apply a human approval decision to an existing approval record.

    This function returns a NEW dict (does not mutate the input).

    Parameters
    ----------
    record    : dict returned by create_approval_record
    decision  : "approved" | "rejected"
    approver  : identifier for the human making the decision (e.g. email)
    timestamp : optional string timestamp; stored as-is (no wall-clock used)

    Returns
    -------
    Updated approval record dict.

    Raises
    ------
    ValueError  – if the record status is immutable, if the decision value
                  is not "approved"/"rejected", or if approver is empty.
    """
    current_status = record.get("status")

    # Guard: immutable states
    if current_status in _IMMUTABLE_STATUSES and current_status != "pending":
        raise ValueError(
            f"Cannot change approval record with status '{current_status}'. "
            f"Blocked and already-decided records are immutable."
        )

    # Guard: valid human decision
    decision_lower = decision.lower() if isinstance(decision, str) else ""
    if decision_lower not in _HUMAN_DECISIONS:
        raise ValueError(
            f"Invalid approval decision '{decision}'. "
            f"Must be one of: {sorted(_HUMAN_DECISIONS)}"
        )

    # Guard: approver must be provided
    if not approver or not str(approver).strip():
        raise ValueError("approver must be a non-empty identifier string.")

    # Guard: only APPROVAL_REQUIRED records can be decided
    if current_status != "pending":
        raise ValueError(
            f"Only 'pending' records can be decided. "
            f"Current status: '{current_status}'."
        )

    updated = dict(record)
    updated["status"]    = decision_lower
    updated["approver"]  = str(approver).strip()
    updated["timestamp"] = timestamp
    updated["notes"]     = (
        f"Action {decision_lower} by {approver}"
        + (f" at {timestamp}" if timestamp else "") + "."
    )
    return updated


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from evaluator import evaluate_action

    for cmd, label in [
        ("deploy to production",            "APPROVAL_REQUIRED"),
        ("DROP TABLE users;",               "BLOCK"),
        ("git push origin main --force",    "BLOCK"),
        ("read src/utils.py",               "ALLOW"),
    ]:
        action = {"tool": "terminal", "command": cmd}
        result = evaluate_action(action)
        rec    = create_approval_record(action, result)
        print(f"\n--- {label} ---")
        print(json.dumps(rec, indent=2, default=str))
