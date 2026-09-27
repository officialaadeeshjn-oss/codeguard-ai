"""
engine/timeline.py
------------------
Replay-timeline builder for CodeGuard AI.

Constructs a chronological, ordered list of discrete events from the real
CodeGuard execution data collected across all phases.

Design principles
-----------------
- Honest: only events whose corresponding data was actually supplied are
  included.  Nothing is fabricated.
- Deterministic: same inputs → same event sequence.
- Ordered: events are assigned monotonically increasing sequence numbers
  starting at 1 in the order they are added.
- Typed: each event has a well-known type string; callers can extend with
  custom events by passing extra events to build_timeline().

Standard event types
--------------------
  PROPOSED               – the action was submitted to CodeGuard
  ANALYZED               – evidence and blast-radius analysis were performed
  POLICY_EVALUATED       – the policy evaluator produced a decision
  BLOCKED                – the evaluator returned BLOCK
  SAFER_PLAN_CREATED     – a safer alternative plan was generated
  SECURITY_TESTS_GENERATED – attack-path test cases were generated
  TESTS_VERIFIED         – all generated tests were run (gate reached a verdict)
  TESTS_FAILED           – one or more generated tests failed
  APPROVAL_REQUESTED     – an APPROVAL_REQUIRED decision was issued
  APPROVED               – a human approver approved the action
  REJECTED               – a human approver rejected the action
  ROLLBACK_VERIFIED      – rollback path was confirmed
  ROLLBACK_UNAVAILABLE   – rollback was explicitly marked as unavailable
  READY_FOR_EXECUTION    – all checks passed; action is cleared

Usage:
    from engine.timeline import build_timeline

    events = build_timeline(
        action          = action,
        eval_result     = evaluate_action(action),
        evidence        = evidence_dict,          # optional
        blast_radius    = blast_radius_dict,       # optional
        safer_plan      = safer_plan_dict,         # optional
        attack_suite    = attack_suite_dict,       # optional
        gate_result     = gate_result_dict,        # optional
        approval_record = approval_record_dict,    # optional
        rollback_result = rollback_result_dict,    # optional
        final_status    = "READY_FOR_EXECUTION",   # optional
        extra_events    = [...],                   # optional caller-supplied
    )
    # events is a list of dicts, each with keys:
    #   seq, event_type, action_summary, decision_or_status,
    #   policy_id, evidence_ref, notes
"""


def _make_event(seq: int,
                event_type: str,
                action_summary: str,
                decision_or_status: str,
                policy_id: str   = None,
                evidence_ref: str = None,
                notes: str       = None) -> dict:
    """Return a single timeline-event dict."""
    return {
        "seq":                seq,
        "event_type":         event_type,
        "action_summary":     action_summary,
        "decision_or_status": decision_or_status,
        "policy_id":          policy_id,
        "evidence_ref":       evidence_ref,
        "notes":              notes,
    }


def _summarise_action(action: dict) -> str:
    """Return a one-line human-readable summary of the action."""
    import json
    tool    = action.get("tool", "unknown-tool")
    cmd     = action.get("command") or action.get("code") or action.get("file_path")
    if cmd and len(str(cmd)) > 80:
        cmd = str(cmd)[:77] + "..."
    return f"{tool}: {cmd}" if cmd else tool


def build_timeline(
    action: dict,
    eval_result: dict,
    evidence: dict         = None,
    blast_radius: dict     = None,
    safer_plan: dict       = None,
    attack_suite: dict     = None,
    gate_result: dict      = None,
    approval_record: dict  = None,
    rollback_result: dict  = None,
    final_status: str      = None,
    extra_events: list     = None,
) -> list:
    """
    Build and return an ordered replay timeline of CodeGuard events.

    Only events whose corresponding data was actually supplied are included.
    Sequence numbers are assigned in the order events are added, starting at 1.

    Parameters
    ----------
    action          : the raw action dict (required)
    eval_result     : dict returned by evaluate_action (required)
    evidence        : dict returned by extract_evidence (optional)
    blast_radius    : dict returned by analyze_blast_radius (optional)
    safer_plan      : dict returned by generate_safer_plan (optional)
    attack_suite    : dict returned by generate_attack_tests (optional)
    gate_result     : dict returned by evaluate_gate (optional)
    approval_record : approval record dict (optional)
    rollback_result : dict returned by verify_rollback (optional)
    final_status    : the trust-receipt final_status string (optional)
    extra_events    : list of additional event dicts to append (optional)

    Returns
    -------
    list of event dicts, each containing:
        seq                – 1-based sequence number
        event_type         – event type string
        action_summary     – one-line description of the action
        decision_or_status – relevant decision or status at this event
        policy_id          – relevant policy ID or None
        evidence_ref       – short reference to related evidence or None
        notes              – optional human-readable note or None
    """
    events        = []
    seq           = 0
    action_text   = _summarise_action(action)
    policy_ids    = [m["policy_id"] for m in eval_result.get("matched_policies", [])]
    policy_id_str = ", ".join(policy_ids) if policy_ids else None

    def add(event_type, decision_or_status,
            policy_id=None, evidence_ref=None, notes=None):
        nonlocal seq
        seq += 1
        events.append(_make_event(
            seq                = seq,
            event_type         = event_type,
            action_summary     = action_text,
            decision_or_status = decision_or_status,
            policy_id          = policy_id,
            evidence_ref       = evidence_ref,
            notes              = notes,
        ))

    # ── Event 1: PROPOSED (always present) ───────────────────────────────────
    add("PROPOSED", "submitted")

    # ── Evidence / blast-radius analysis ────────────────────────────────────
    if evidence or blast_radius:
        ref_parts = []
        if evidence:
            ref_parts.append(f"affected_file={evidence.get('affected_file', 'N/A')}")
        if blast_radius:
            n_api = len(blast_radius.get("affected_api_endpoints", []))
            n_db  = len(blast_radius.get("affected_db_components", []))
            ref_parts.append(f"api_components={n_api}, db_components={n_db}")
        add("ANALYZED",
            "evidence and blast-radius collected",
            evidence_ref="; ".join(ref_parts) if ref_parts else None)

    # ── Policy evaluation ────────────────────────────────────────────────────
    policy_decision = eval_result.get("decision", "ALLOW")
    add("POLICY_EVALUATED",
        policy_decision,
        policy_id=policy_id_str,
        notes=f"Matched policies: {policy_id_str}" if policy_id_str else "No policies matched")

    # ── BLOCKED branch ───────────────────────────────────────────────────────
    if policy_decision == "BLOCK":
        add("BLOCKED",
            "BLOCK",
            policy_id=policy_id_str,
            notes="Action is permanently blocked. No approval can override.")

    # ── Safer plan ───────────────────────────────────────────────────────────
    if safer_plan:
        n_steps = len(safer_plan.get("safer_steps", []))
        add("SAFER_PLAN_CREATED",
            "safer plan available",
            policy_id=policy_id_str,
            notes=f"{n_steps} safer step(s) generated")

    # ── Security tests ───────────────────────────────────────────────────────
    if attack_suite:
        n_tests = attack_suite.get("total", 0)
        add("SECURITY_TESTS_GENERATED",
            f"{n_tests} test(s) generated",
            policy_id=policy_id_str,
            notes=f"Test IDs: {[tc['id'] for tc in attack_suite.get('test_cases', [])]}")

    if gate_result:
        verdict = gate_result.get("verdict", "NOT_RUN")
        if verdict == "FAIL":
            add("TESTS_FAILED",
                "FAIL",
                policy_id=policy_id_str,
                notes=f"{gate_result.get('failed', 0)} test(s) failed")
        else:
            add("TESTS_VERIFIED",
                verdict,
                notes=gate_result.get("summary", ""))

    # ── Approval ─────────────────────────────────────────────────────────────
    if approval_record:
        status = approval_record.get("status", "unknown")

        if status == "pending":
            add("APPROVAL_REQUESTED",
                "pending",
                policy_id=policy_id_str,
                notes="Waiting for human approver")
        elif status == "approved":
            approver  = approval_record.get("approver")   or "unknown"
            timestamp = approval_record.get("timestamp")
            ts_note   = f" at {timestamp}" if timestamp else ""
            add("APPROVAL_REQUESTED",
                "was pending",
                policy_id=policy_id_str)
            add("APPROVED",
                "approved",
                policy_id=policy_id_str,
                notes=f"Approved by {approver}{ts_note}")
        elif status == "rejected":
            approver  = approval_record.get("approver")   or "unknown"
            timestamp = approval_record.get("timestamp")
            ts_note   = f" at {timestamp}" if timestamp else ""
            add("APPROVAL_REQUESTED",
                "was pending",
                policy_id=policy_id_str)
            add("REJECTED",
                "rejected",
                policy_id=policy_id_str,
                notes=f"Rejected by {approver}{ts_note}")
        # blocked / not_required → no approval events added

    # ── Rollback ─────────────────────────────────────────────────────────────
    if rollback_result:
        verdict = rollback_result.get("verdict", "NOT_VERIFIED")
        signals = rollback_result.get("positive_signals", [])
        if verdict == "AVAILABLE":
            add("ROLLBACK_VERIFIED",
                "AVAILABLE",
                notes=f"Signals: {', '.join(signals)}" if signals else None)
        elif verdict == "UNAVAILABLE":
            add("ROLLBACK_UNAVAILABLE",
                "UNAVAILABLE",
                notes="Rollback explicitly marked as unavailable")
        # NOT_VERIFIED → no rollback event (absence is honest)

    # ── Final status ─────────────────────────────────────────────────────────
    if final_status == "READY_FOR_EXECUTION":
        add("READY_FOR_EXECUTION",
            "READY_FOR_EXECUTION",
            notes="All CodeGuard checks passed or are not applicable")

    # ── Caller-supplied extra events ─────────────────────────────────────────
    if extra_events:
        for ev in extra_events:
            seq += 1
            event = dict(ev)
            event["seq"] = seq
            # Ensure action_summary is set
            if "action_summary" not in event:
                event["action_summary"] = action_text
            events.append(event)

    return events


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

    from evaluator    import evaluate_action
    from evidence     import extract_evidence
    from blast_radius import analyze_blast_radius
    from safer_plan   import generate_safer_plan
    from attack_tests import generate_attack_tests
    from test_gate    import evaluate_gate
    from approval     import create_approval_record, decide_approval
    from rollback     import verify_rollback

    action      = {"tool": "terminal", "command": "deploy to production"}
    eval_result = evaluate_action(action)
    ev          = extract_evidence(action, eval_result)
    br          = analyze_blast_radius(action, eval_result)
    sp          = generate_safer_plan(action, eval_result, ev)
    suite       = generate_attack_tests(action, eval_result)
    all_pass    = {tc["id"]: "pass" for tc in suite["test_cases"]}
    gate        = evaluate_gate(suite, all_pass)
    rec         = create_approval_record(action, eval_result)
    rec         = decide_approval(rec, "approved", "alice@example.com",
                                  "2024-01-15T10:00:00Z")
    rb          = verify_rollback({"deployment_rollback": True})

    timeline = build_timeline(
        action          = action,
        eval_result     = eval_result,
        evidence        = ev,
        blast_radius    = br,
        safer_plan      = sp,
        attack_suite    = suite,
        gate_result     = gate,
        approval_record = rec,
        rollback_result = rb,
        final_status    = "READY_FOR_EXECUTION",
    )
    print(json.dumps(timeline, indent=2, default=str))
