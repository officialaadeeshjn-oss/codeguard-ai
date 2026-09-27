"""
engine/trust_receipt.py
-----------------------
Trust Receipt builder for CodeGuard AI.

Produces a structured, immutable Trust Receipt from real CodeGuard execution
data collected by the upstream Phase 2–5 components.

Design principles
-----------------
- Honest: never invents counts, statuses, or facts.
- Deterministic: same inputs → same receipt.
- Explicit about gaps: missing information is represented as the string
  "NOT_AVAILABLE", "NOT_RUN", or "NOT_VERIFIED" rather than fabricated.
- Composable: all fields are sourced directly from the supplied dicts;
  this module only assembles and derives, never guesses.

Final-status rules (applied in order)
--------------------------------------
1. BLOCKED              – policy decision is BLOCK
2. REJECTED             – approval was explicitly rejected
3. APPROVAL_REQUIRED    – approval is required but still pending
4. VERIFICATION_FAILED  – any security test result is "fail"
5. ROLLBACK_NOT_VERIFIED – rollback is NOT_VERIFIED and the policy decision
                           is APPROVAL_REQUIRED (higher-risk change requires
                           known rollback path)
6. READY_FOR_EXECUTION  – all of the above conditions are absent

Usage:
    from engine.trust_receipt import build_trust_receipt

    receipt = build_trust_receipt(
        receipt_id      = "receipt-001",
        action          = action,
        eval_result     = evaluate_action(action),
        evidence        = extract_evidence(action, eval_result),
        blast_radius    = analyze_blast_radius(action, eval_result),
        safer_plan      = generate_safer_plan(action, eval_result),
        attack_suite    = generate_attack_tests(action, eval_result),
        gate_result     = evaluate_gate(attack_suite, actual_results),
        approval_record = approval_record,
        rollback_result = rollback_result,
    )
"""

# Sentinel string for genuinely absent optional information
_NA  = "NOT_AVAILABLE"
_NR  = "NOT_RUN"
_NV  = "NOT_VERIFIED"


def build_trust_receipt(
    receipt_id: str,
    action: dict,
    eval_result: dict,
    evidence: dict       = None,
    blast_radius: dict   = None,
    safer_plan: dict     = None,
    attack_suite: dict   = None,
    gate_result: dict    = None,
    approval_record: dict = None,
    rollback_result: dict = None,
) -> dict:
    """
    Build and return a structured Trust Receipt.

    All parameters except receipt_id, action, and eval_result are optional.
    Missing components are represented with explicit sentinel strings rather
    than fabricated values.

    Parameters
    ----------
    receipt_id      : caller-supplied identifier for this receipt
    action          : the raw action dict
    eval_result     : dict returned by evaluate_action (required)
    evidence        : dict returned by extract_evidence (optional)
    blast_radius    : dict returned by analyze_blast_radius (optional)
    safer_plan      : dict returned by generate_safer_plan (optional)
    attack_suite    : dict returned by generate_attack_tests (optional)
    gate_result     : dict returned by evaluate_gate (optional)
    approval_record : dict returned by create_approval_record /
                      decide_approval (optional)
    rollback_result : dict returned by verify_rollback (optional)

    Returns
    -------
    dict with keys:
        receipt_id
        action
        policy_decision
        matched_policy_ids
        decision_states         – per-policy {id, decision, reason}
        evidence_summary        – key evidence fields or NOT_AVAILABLE
        blast_radius_summary    – key blast-radius fields or NOT_AVAILABLE
        safer_plan_summary      – key safer-plan fields or NOT_AVAILABLE
        security_tests          – test cases with actual status, or NOT_RUN
        test_gate_verdict       – PASS / FAIL / NOT_RUN / NOT_AVAILABLE
        approval_status         – approval status string or NOT_AVAILABLE
        approver                – approver identifier or NOT_AVAILABLE
        rollback_verdict        – rollback verdict or NOT_VERIFIED
        final_status            – one of the six final-status values
        final_status_reason     – explanation of the final status
    """
    # ── Policy evaluation (always required) ──────────────────────────────────
    policy_decision  = eval_result.get("decision", "ALLOW")
    matched_policies = eval_result.get("matched_policies", [])
    matched_ids      = [m["policy_id"] for m in matched_policies]

    decision_states = [
        {"id": m["policy_id"], "decision": m["decision"], "reason": m["reason"]}
        for m in matched_policies
    ] or _NA

    # ── Evidence ─────────────────────────────────────────────────────────────
    if evidence:
        evidence_summary = {
            "tool":          evidence.get("tool",          _NA),
            "affected_file": evidence.get("affected_file", _NA),
            "code_location": evidence.get("code_location", _NA),
            "api_component": evidence.get("api_component", _NA),
            "db_component":  evidence.get("db_component",  _NA),
            "notes":         evidence.get("notes",         []),
        }
    else:
        evidence_summary = _NA

    # ── Blast radius ─────────────────────────────────────────────────────────
    if blast_radius:
        blast_radius_summary = {
            "affected_files":         blast_radius.get("affected_files",         []),
            "affected_api_endpoints": blast_radius.get("affected_api_endpoints", []),
            "affected_db_components": blast_radius.get("affected_db_components", []),
            "affected_tests":         blast_radius.get("affected_tests",         []),
            "deployment_impact":      blast_radius.get("deployment_impact",      False),
        }
    else:
        blast_radius_summary = _NA

    # ── Safer plan ───────────────────────────────────────────────────────────
    if safer_plan:
        safer_plan_summary = {
            "matched_policy_ids":  safer_plan.get("matched_policy_ids", []),
            "why_unsafe":          safer_plan.get("why_unsafe",         []),
            "safer_steps":         safer_plan.get("safer_steps",        []),
            "verification_steps":  safer_plan.get("verification_steps", []),
            "affected_components": safer_plan.get("affected_components",[]),
            "disclaimer":          safer_plan.get("disclaimer",         _NA),
        }
    else:
        safer_plan_summary = _NA

    # ── Security tests ───────────────────────────────────────────────────────
    if attack_suite and gate_result:
        # Merge test-case descriptions with per-test gate statuses
        gate_map = {
            tr["id"]: tr["status"]
            for tr in gate_result.get("test_results", [])
        }
        security_tests = []
        for tc in attack_suite.get("test_cases", []):
            tc_id  = tc.get("id", "")
            status = gate_map.get(tc_id, _NR)
            security_tests.append({
                "id":          tc_id,
                "name":        tc.get("name",        ""),
                "policy_id":   tc.get("policy_id",   ""),
                "category":    tc.get("category",    ""),
                "description": tc.get("description", ""),
                "status":      status,
            })
        test_gate_verdict = gate_result.get("verdict", _NA)
    elif attack_suite and not gate_result:
        # Tests generated but not run
        security_tests = [
            dict(tc, status=_NR) for tc in attack_suite.get("test_cases", [])
        ]
        test_gate_verdict = _NR
    else:
        security_tests    = _NR
        test_gate_verdict = _NA

    # ── Approval ─────────────────────────────────────────────────────────────
    if approval_record:
        approval_status = approval_record.get("status",   _NA)
        approver        = approval_record.get("approver") or _NA
    else:
        approval_status = _NA
        approver        = _NA

    # ── Rollback ─────────────────────────────────────────────────────────────
    rollback_verdict = (
        rollback_result.get("verdict", _NV)
        if rollback_result else _NV
    )

    # ── Final status (rules applied in order) ────────────────────────────────
    final_status, final_reason = _derive_final_status(
        policy_decision  = policy_decision,
        approval_status  = approval_status,
        gate_result      = gate_result,
        rollback_verdict = rollback_verdict,
    )

    return {
        "receipt_id":           receipt_id,
        "action":               action,
        "policy_decision":      policy_decision,
        "matched_policy_ids":   matched_ids,
        "decision_states":      decision_states,
        "evidence_summary":     evidence_summary,
        "blast_radius_summary": blast_radius_summary,
        "safer_plan_summary":   safer_plan_summary,
        "security_tests":       security_tests,
        "test_gate_verdict":    test_gate_verdict,
        "approval_status":      approval_status,
        "approver":             approver,
        "rollback_verdict":     rollback_verdict,
        "final_status":         final_status,
        "final_status_reason":  final_reason,
    }


# ---------------------------------------------------------------------------
# Final-status derivation
# ---------------------------------------------------------------------------

def _derive_final_status(policy_decision: str,
                         approval_status: str,
                         gate_result,
                         rollback_verdict: str) -> tuple:
    """
    Apply the deterministic final-status rules and return (status, reason).
    """
    # Rule 1 – BLOCKED
    if policy_decision == "BLOCK":
        return (
            "BLOCKED",
            "A BLOCK policy decision was not resolved. "
            "No approval can override a BLOCK.",
        )

    # Rule 2 – REJECTED
    if approval_status == "rejected":
        return (
            "REJECTED",
            "The approval request was explicitly rejected by the approver.",
        )

    # Rule 3 – APPROVAL_REQUIRED (still pending)
    if policy_decision == "APPROVAL_REQUIRED" and approval_status not in (
        "approved", "not_required"
    ):
        return (
            "APPROVAL_REQUIRED",
            "This action requires human approval before execution. "
            f"Current approval status: {approval_status}.",
        )

    # Rule 4 – VERIFICATION_FAILED
    if gate_result and gate_result.get("verdict") == "FAIL":
        n_failed = gate_result.get("failed", 0)
        return (
            "VERIFICATION_FAILED",
            f"{n_failed} security test(s) failed. "
            "Resolve all test failures before proceeding.",
        )

    # Rule 5 – ROLLBACK_NOT_VERIFIED (only for higher-risk changes)
    if (policy_decision == "APPROVAL_REQUIRED"
            and rollback_verdict == "NOT_VERIFIED"):
        return (
            "ROLLBACK_NOT_VERIFIED",
            "Rollback availability was not verified for an action that "
            "requires approval. Provide rollback evidence before proceeding.",
        )

    # Rule 6 – READY_FOR_EXECUTION
    return (
        "READY_FOR_EXECUTION",
        "All CodeGuard checks passed or are not applicable. "
        "Action is cleared for execution.",
    )


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

    receipt = build_trust_receipt(
        receipt_id      = "demo-receipt-001",
        action          = action,
        eval_result     = eval_result,
        evidence        = ev,
        blast_radius    = br,
        safer_plan      = sp,
        attack_suite    = suite,
        gate_result     = gate,
        approval_record = rec,
        rollback_result = rb,
    )
    print(json.dumps(receipt, indent=2, default=str))
