"""
engine/audit_event.py
---------------------
Audit-event builder for CodeGuard AI.

Creates a structured, immutable snapshot connecting:
  - the original proposed action
  - the policy evaluation decision
  - the approval status
  - the rollback status

This record is designed to feed the Trust Receipt (Phase 6) and any
audit log.  It does NOT write to disk or make any external calls.

Design principles
-----------------
- Deterministic: same inputs → same event.
- Composable: each field is sourced from one of the Phase 2–5 components;
  nothing is invented here.
- Honest: status values are taken directly from the upstream components;
  this module never upgrades or downgrades them.

Event status
------------
The top-level "status" field summarises the combined state:

  PERMITTED        – decision is ALLOW or (APPROVAL_REQUIRED + approved)
                     AND rollback is AVAILABLE or NOT_VERIFIED
  PERMITTED_NO_ROLLBACK
                   – decision is ALLOW/approved BUT rollback is UNAVAILABLE
                     (action is permitted but carries rollback risk)
  PENDING_APPROVAL – decision is APPROVAL_REQUIRED and approval is still pending
  REJECTED         – decision is APPROVAL_REQUIRED and approval was rejected
  BLOCKED          – decision is BLOCK (no approval can change this)

Usage:
    from engine.audit_event import build_audit_event

    event = build_audit_event(
        action          = action,
        eval_result     = evaluate_action(action),
        approval_record = create_approval_record(action, eval_result),
        rollback_result = verify_rollback({"backup_available": True}),
    )
"""


def build_audit_event(action: dict,
                      eval_result: dict,
                      approval_record: dict,
                      rollback_result: dict) -> dict:
    """
    Build a structured audit event.

    Parameters
    ----------
    action          : the raw action dict
    eval_result     : dict returned by evaluate_action
    approval_record : dict returned by create_approval_record
                      (possibly updated by decide_approval)
    rollback_result : dict returned by verify_rollback

    Returns
    -------
    dict with keys:
        action              – the original action
        policy_decision     – the evaluator's final decision string
        matched_policy_ids  – list of matched policy IDs
        approval_status     – the approval record's status string
        approver            – the approver identifier or None
        approval_timestamp  – the approval timestamp or None
        rollback_verdict    – the rollback verdict string
        rollback_signals    – list of positive rollback evidence keys
        status              – combined event status (see module docstring)
        summary             – one-line human-readable description
    """
    policy_decision    = eval_result.get("decision", "ALLOW")
    matched_policies   = eval_result.get("matched_policies", [])
    matched_ids        = [m["policy_id"] for m in matched_policies]

    approval_status    = approval_record.get("status", "not_required")
    approver           = approval_record.get("approver")
    approval_timestamp = approval_record.get("timestamp")

    rollback_verdict   = rollback_result.get("verdict", "NOT_VERIFIED")
    rollback_signals   = rollback_result.get("positive_signals", [])

    # Derive combined event status
    if policy_decision == "BLOCK":
        status  = "BLOCKED"
        summary = (
            f"Action is BLOCKED by policy "
            f"({', '.join(matched_ids) or 'unknown'}). "
            f"No approval can override a BLOCK."
        )
    elif policy_decision == "APPROVAL_REQUIRED":
        if approval_status == "approved":
            if rollback_verdict == "UNAVAILABLE":
                status  = "PERMITTED_NO_ROLLBACK"
                summary = (
                    "Action was approved but rollback is unavailable. "
                    "Proceed with caution."
                )
            else:
                status  = "PERMITTED"
                summary = (
                    f"Action approved by {approver or 'unknown'}"
                    + (f" at {approval_timestamp}" if approval_timestamp else "")
                    + ". Rollback: " + rollback_verdict + "."
                )
        elif approval_status == "rejected":
            status  = "REJECTED"
            summary = (
                f"Action rejected by {approver or 'unknown'}"
                + (f" at {approval_timestamp}" if approval_timestamp else "") + "."
            )
        else:
            # pending or any unexpected value
            status  = "PENDING_APPROVAL"
            summary = (
                f"Action requires human approval "
                f"(policy: {', '.join(matched_ids) or 'unknown'}). "
                f"Currently: {approval_status}."
            )
    else:
        # ALLOW or WARN
        if rollback_verdict == "UNAVAILABLE":
            status  = "PERMITTED_NO_ROLLBACK"
            summary = (
                f"Action decision is {policy_decision} but rollback is "
                f"unavailable. Proceed with caution."
            )
        else:
            status  = "PERMITTED"
            summary = (
                f"Action decision is {policy_decision}. "
                f"Rollback: {rollback_verdict}."
            )

    return {
        "action":              action,
        "policy_decision":     policy_decision,
        "matched_policy_ids":  matched_ids,
        "approval_status":     approval_status,
        "approver":            approver,
        "approval_timestamp":  approval_timestamp,
        "rollback_verdict":    rollback_verdict,
        "rollback_signals":    rollback_signals,
        "status":              status,
        "summary":             summary,
    }


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

    from evaluator import evaluate_action
    from approval  import create_approval_record, decide_approval
    from rollback  import verify_rollback

    # Scenario: production deploy → approved with backup
    action      = {"tool": "terminal", "command": "deploy to production"}
    eval_result = evaluate_action(action)
    rec         = create_approval_record(action, eval_result)
    rec         = decide_approval(rec, "approved", "alice@example.com",
                                  timestamp="2024-01-15T10:00:00Z")
    rollback    = verify_rollback({"deployment_rollback": True})
    event       = build_audit_event(action, eval_result, rec, rollback)
    print(json.dumps(event, indent=2, default=str))
