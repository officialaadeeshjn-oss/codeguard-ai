"""
engine/test_phase6.py
---------------------
Automated tests for Phase 6 components:
  - trust_receipt.build_trust_receipt()
  - timeline.build_timeline()

Run with:
    python -m pytest engine/test_phase6.py -v
or:
    python engine/test_phase6.py

These tests do NOT modify the evaluator or any Phase 2–5 tests.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evaluator     import evaluate_action
from evidence      import extract_evidence
from blast_radius  import analyze_blast_radius
from safer_plan    import generate_safer_plan
from attack_tests  import generate_attack_tests
from test_gate     import evaluate_gate
from approval      import create_approval_record, decide_approval
from rollback      import verify_rollback
from trust_receipt import build_trust_receipt
from timeline      import build_timeline


# ---------------------------------------------------------------------------
# Shared scenario builders
# ---------------------------------------------------------------------------

def _allow_action():
    return {"tool": "read_file", "file_path": "src/utils.py"}

def _deploy_action():
    return {"tool": "terminal", "command": "deploy to production"}

def _block_action():
    return {"tool": "terminal", "command": "DROP TABLE users;"}

def _otp_action():
    return {"tool": "edit_file",
            "command": "store reset token plaintext in database"}


def _full_receipt(action,
                  approval_decision=None,
                  approver="test-approver",
                  rollback_evidence=None,
                  gate_actual=None):
    """Build a complete trust receipt from scratch for the given action."""
    eval_result = evaluate_action(action)
    ev          = extract_evidence(action, eval_result)
    br          = analyze_blast_radius(action, eval_result)
    sp          = generate_safer_plan(action, eval_result, ev)
    suite       = generate_attack_tests(action, eval_result)

    if gate_actual is not None:
        gate = evaluate_gate(suite, gate_actual)
    else:
        gate = None

    rec = create_approval_record(action, eval_result)
    if approval_decision and rec["status"] == "pending":
        rec = decide_approval(rec, approval_decision, approver=approver)

    rb = verify_rollback(rollback_evidence or {})

    return build_trust_receipt(
        receipt_id      = "test-receipt",
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


# ===========================================================================
# SECTION A — Trust Receipt structure and content
# ===========================================================================

class TestTrustReceiptContent:

    def test_contains_required_keys(self):
        """build_trust_receipt must return all required top-level keys."""
        receipt = _full_receipt(_allow_action())
        required = {
            "receipt_id", "action", "policy_decision", "matched_policy_ids",
            "decision_states", "evidence_summary", "blast_radius_summary",
            "safer_plan_summary", "security_tests", "test_gate_verdict",
            "approval_status", "approver", "rollback_verdict",
            "final_status", "final_status_reason",
        }
        missing = required - set(receipt.keys())
        assert not missing, f"Missing keys: {missing}"
        print("PASS  test_contains_required_keys")

    def test_action_is_preserved(self):
        """The original action dict must appear unchanged in the receipt."""
        action  = _deploy_action()
        receipt = _full_receipt(action)
        assert receipt["action"] == action, (
            "action field does not match the original"
        )
        print("PASS  test_action_is_preserved")

    def test_policy_ids_are_preserved(self):
        """Matched policy IDs from the evaluator must appear in the receipt."""
        action      = _block_action()
        eval_result = evaluate_action(action)
        expected    = [m["policy_id"] for m in eval_result["matched_policies"]]
        receipt     = _full_receipt(action)
        assert receipt["matched_policy_ids"] == expected, (
            f"Expected {expected}, got {receipt['matched_policy_ids']}"
        )
        print("PASS  test_policy_ids_are_preserved")

    def test_evidence_is_preserved(self):
        """Evidence fields must be forwarded into the receipt."""
        action      = _deploy_action()
        eval_result = evaluate_action(action)
        ev          = extract_evidence(action, eval_result)
        rb          = verify_rollback({})
        rec         = create_approval_record(action, eval_result)
        receipt = build_trust_receipt(
            receipt_id      = "t",
            action          = action,
            eval_result     = eval_result,
            evidence        = ev,
            approval_record = rec,
            rollback_result = rb,
        )
        assert receipt["evidence_summary"] != "NOT_AVAILABLE", (
            "evidence_summary should be populated when evidence is supplied"
        )
        assert receipt["evidence_summary"]["tool"] == "terminal"
        print("PASS  test_evidence_is_preserved")

    def test_blast_radius_is_preserved(self):
        """Blast-radius data must appear in the receipt when supplied."""
        action      = _deploy_action()
        eval_result = evaluate_action(action)
        br          = analyze_blast_radius(action, eval_result)
        rb          = verify_rollback({})
        rec         = create_approval_record(action, eval_result)
        receipt = build_trust_receipt(
            receipt_id      = "t",
            action          = action,
            eval_result     = eval_result,
            blast_radius    = br,
            approval_record = rec,
            rollback_result = rb,
        )
        assert receipt["blast_radius_summary"] != "NOT_AVAILABLE"
        assert "deployment_impact" in receipt["blast_radius_summary"]
        print("PASS  test_blast_radius_is_preserved")

    def test_security_test_results_are_preserved(self):
        """Actual test statuses must be embedded in security_tests."""
        action      = _otp_action()
        eval_result = evaluate_action(action)
        suite       = generate_attack_tests(action, eval_result)
        all_pass    = {tc["id"]: "pass" for tc in suite["test_cases"]}
        gate        = evaluate_gate(suite, all_pass)
        rb          = verify_rollback({})
        rec         = create_approval_record(action, eval_result)
        receipt = build_trust_receipt(
            receipt_id      = "t",
            action          = action,
            eval_result     = eval_result,
            attack_suite    = suite,
            gate_result     = gate,
            approval_record = rec,
            rollback_result = rb,
        )
        assert isinstance(receipt["security_tests"], list)
        statuses = {tc["status"] for tc in receipt["security_tests"]}
        assert statuses == {"pass"}, (
            f"Expected all 'pass' statuses, got {statuses}"
        )
        print("PASS  test_security_test_results_are_preserved")

    def test_approval_status_is_preserved(self):
        """The approval status must be forwarded into the receipt."""
        receipt = _full_receipt(_deploy_action(), approval_decision="approved")
        assert receipt["approval_status"] == "approved"
        print("PASS  test_approval_status_is_preserved")

    def test_rollback_verdict_is_preserved(self):
        """The rollback verdict must be forwarded into the receipt."""
        receipt = _full_receipt(
            _deploy_action(),
            rollback_evidence={"deployment_rollback": True}
        )
        assert receipt["rollback_verdict"] == "AVAILABLE"
        print("PASS  test_rollback_verdict_is_preserved")


# ===========================================================================
# SECTION B — Final-status rules
# ===========================================================================

class TestFinalStatus:

    def test_block_produces_blocked_status(self):
        """An unresolved BLOCK must produce final_status BLOCKED."""
        receipt = _full_receipt(_block_action())
        assert receipt["final_status"] == "BLOCKED", (
            f"Expected BLOCKED, got {receipt['final_status']}"
        )
        print("PASS  test_block_produces_blocked_status")

    def test_pending_approval_produces_approval_required(self):
        """Pending approval on APPROVAL_REQUIRED → APPROVAL_REQUIRED."""
        action      = _deploy_action()
        eval_result = evaluate_action(action)
        rec         = create_approval_record(action, eval_result)
        # do NOT approve — leave pending
        rb          = verify_rollback({})
        receipt = build_trust_receipt(
            receipt_id      = "t",
            action          = action,
            eval_result     = eval_result,
            approval_record = rec,
            rollback_result = rb,
        )
        assert receipt["final_status"] == "APPROVAL_REQUIRED", (
            f"Expected APPROVAL_REQUIRED, got {receipt['final_status']}"
        )
        print("PASS  test_pending_approval_produces_approval_required")

    def test_failed_tests_produce_verification_failed(self):
        """A failed test gate must produce VERIFICATION_FAILED.

        Uses the production-deployment action (APPROVAL_REQUIRED, not BLOCK)
        so that the BLOCK rule does not fire before VERIFICATION_FAILED.
        The action is approved so rule 3 (pending approval) is also bypassed,
        letting rule 4 (failed tests) trigger.
        """
        action      = _deploy_action()          # APPROVAL_REQUIRED, not BLOCK
        eval_result = evaluate_action(action)
        suite       = generate_attack_tests(action, eval_result)
        # fail the first test only
        fail_map    = {tc["id"]: "fail" for tc in suite["test_cases"][:1]}
        gate        = evaluate_gate(suite, fail_map)
        rb          = verify_rollback({"deployment_rollback": True})
        rec         = create_approval_record(action, eval_result)
        rec         = decide_approval(rec, "approved", approver="alice")
        receipt = build_trust_receipt(
            receipt_id      = "t",
            action          = action,
            eval_result     = eval_result,
            attack_suite    = suite,
            gate_result     = gate,
            approval_record = rec,
            rollback_result = rb,
        )
        assert receipt["final_status"] == "VERIFICATION_FAILED", (
            f"Expected VERIFICATION_FAILED, got {receipt['final_status']}"
        )
        print("PASS  test_failed_tests_produce_verification_failed")

    def test_unverified_rollback_on_approval_required_action(self):
        """Approved APPROVAL_REQUIRED action with no rollback evidence
        → ROLLBACK_NOT_VERIFIED."""
        action      = _deploy_action()
        eval_result = evaluate_action(action)
        suite       = generate_attack_tests(action, eval_result)
        all_pass    = {tc["id"]: "pass" for tc in suite["test_cases"]}
        gate        = evaluate_gate(suite, all_pass)
        rec         = create_approval_record(action, eval_result)
        rec         = decide_approval(rec, "approved", approver="alice")
        rb          = verify_rollback({})          # NOT_VERIFIED
        receipt = build_trust_receipt(
            receipt_id      = "t",
            action          = action,
            eval_result     = eval_result,
            attack_suite    = suite,
            gate_result     = gate,
            approval_record = rec,
            rollback_result = rb,
        )
        assert receipt["final_status"] == "ROLLBACK_NOT_VERIFIED", (
            f"Expected ROLLBACK_NOT_VERIFIED, got {receipt['final_status']}"
        )
        print("PASS  test_unverified_rollback_on_approval_required_action")

    def test_fully_verified_produces_ready_for_execution(self):
        """Approved action, all tests pass, rollback available
        → READY_FOR_EXECUTION."""
        action      = _deploy_action()
        eval_result = evaluate_action(action)
        suite       = generate_attack_tests(action, eval_result)
        all_pass    = {tc["id"]: "pass" for tc in suite["test_cases"]}
        gate        = evaluate_gate(suite, all_pass)
        rec         = create_approval_record(action, eval_result)
        rec         = decide_approval(rec, "approved", approver="alice")
        rb          = verify_rollback({"deployment_rollback": True})
        receipt = build_trust_receipt(
            receipt_id      = "t",
            action          = action,
            eval_result     = eval_result,
            attack_suite    = suite,
            gate_result     = gate,
            approval_record = rec,
            rollback_result = rb,
        )
        assert receipt["final_status"] == "READY_FOR_EXECUTION", (
            f"Expected READY_FOR_EXECUTION, got {receipt['final_status']}"
        )
        print("PASS  test_fully_verified_produces_ready_for_execution")

    def test_allow_action_is_ready_for_execution(self):
        """A safe ALLOW action with no blockers → READY_FOR_EXECUTION."""
        receipt = _full_receipt(_allow_action())
        assert receipt["final_status"] == "READY_FOR_EXECUTION", (
            f"Expected READY_FOR_EXECUTION for safe action, "
            f"got {receipt['final_status']}"
        )
        print("PASS  test_allow_action_is_ready_for_execution")

    def test_rejected_approval_produces_rejected(self):
        """A rejected approval must produce final_status REJECTED."""
        receipt = _full_receipt(_deploy_action(), approval_decision="rejected")
        assert receipt["final_status"] == "REJECTED", (
            f"Expected REJECTED, got {receipt['final_status']}"
        )
        print("PASS  test_rejected_approval_produces_rejected")

    def test_missing_info_is_not_available_not_fabricated(self):
        """When optional components are omitted, fields show NOT_AVAILABLE
        rather than fabricated values."""
        action      = _allow_action()
        eval_result = evaluate_action(action)
        receipt = build_trust_receipt(
            receipt_id  = "t",
            action      = action,
            eval_result = eval_result,
            # All optional args omitted
        )
        assert receipt["evidence_summary"]     == "NOT_AVAILABLE"
        assert receipt["blast_radius_summary"] == "NOT_AVAILABLE"
        assert receipt["safer_plan_summary"]   == "NOT_AVAILABLE"
        assert receipt["security_tests"]       == "NOT_RUN"
        assert receipt["test_gate_verdict"]    == "NOT_AVAILABLE"
        assert receipt["rollback_verdict"]     == "NOT_VERIFIED"
        print("PASS  test_missing_info_is_not_available_not_fabricated")


# ===========================================================================
# SECTION C — Replay Timeline
# ===========================================================================

class TestTimeline:

    def _full_timeline(self, action,
                       approval_decision=None,
                       approver="test-approver",
                       rollback_evidence=None,
                       gate_actual=None,
                       final_status=None):
        eval_result = evaluate_action(action)
        ev          = extract_evidence(action, eval_result)
        br          = analyze_blast_radius(action, eval_result)
        sp          = generate_safer_plan(action, eval_result, ev)
        suite       = generate_attack_tests(action, eval_result)
        gate        = None
        if gate_actual is not None:
            gate = evaluate_gate(suite, gate_actual)
        rec = create_approval_record(action, eval_result)
        if approval_decision and rec["status"] == "pending":
            rec = decide_approval(rec, approval_decision, approver=approver)
        rb = verify_rollback(rollback_evidence or {})
        return build_timeline(
            action          = action,
            eval_result     = eval_result,
            evidence        = ev,
            blast_radius    = br,
            safer_plan      = sp,
            attack_suite    = suite,
            gate_result     = gate,
            approval_record = rec,
            rollback_result = rb,
            final_status    = final_status,
        )

    def test_returns_non_empty_list(self):
        """build_timeline must return a non-empty list."""
        events = self._full_timeline(_allow_action())
        assert isinstance(events, list) and len(events) > 0
        print("PASS  test_returns_non_empty_list")

    def test_first_event_is_proposed(self):
        """The first event must always be PROPOSED with seq=1."""
        events = self._full_timeline(_allow_action())
        assert events[0]["event_type"] == "PROPOSED"
        assert events[0]["seq"] == 1
        print("PASS  test_first_event_is_proposed")

    def test_sequence_numbers_are_monotonic(self):
        """Sequence numbers must be strictly increasing from 1."""
        events = self._full_timeline(_deploy_action(),
                                     approval_decision="approved",
                                     rollback_evidence={"deployment_rollback": True},
                                     final_status="READY_FOR_EXECUTION")
        seqs = [e["seq"] for e in events]
        assert seqs == list(range(1, len(seqs) + 1)), (
            f"Sequence numbers are not monotonic: {seqs}"
        )
        print("PASS  test_sequence_numbers_are_monotonic")

    def test_event_order_is_preserved(self):
        """Events must appear in logical order: PROPOSED before
        POLICY_EVALUATED before APPROVED."""
        events = self._full_timeline(_deploy_action(),
                                     approval_decision="approved",
                                     rollback_evidence={"deployment_rollback": True})
        types = [e["event_type"] for e in events]
        assert types.index("PROPOSED") < types.index("POLICY_EVALUATED"), (
            "PROPOSED must come before POLICY_EVALUATED"
        )
        assert types.index("POLICY_EVALUATED") < types.index("APPROVED"), (
            "POLICY_EVALUATED must come before APPROVED"
        )
        print("PASS  test_event_order_is_preserved")

    def test_blocked_action_contains_blocked_event(self):
        """A BLOCK decision must produce a BLOCKED event in the timeline."""
        events = self._full_timeline(_block_action())
        types  = [e["event_type"] for e in events]
        assert "BLOCKED" in types, (
            f"Expected BLOCKED event for DROP TABLE action, got: {types}"
        )
        print("PASS  test_blocked_action_contains_blocked_event")

    def test_approved_action_contains_approved_event(self):
        """An approved APPROVAL_REQUIRED action must contain APPROVED event."""
        events = self._full_timeline(_deploy_action(),
                                     approval_decision="approved")
        types  = [e["event_type"] for e in events]
        assert "APPROVED" in types, (
            f"Expected APPROVED event, got: {types}"
        )
        print("PASS  test_approved_action_contains_approved_event")

    def test_rollback_available_produces_rollback_verified_event(self):
        """Rollback AVAILABLE must produce a ROLLBACK_VERIFIED event."""
        events = self._full_timeline(_deploy_action(),
                                     rollback_evidence={"deployment_rollback": True})
        types  = [e["event_type"] for e in events]
        assert "ROLLBACK_VERIFIED" in types, (
            f"Expected ROLLBACK_VERIFIED event, got: {types}"
        )
        print("PASS  test_rollback_available_produces_rollback_verified_event")

    def test_rollback_unavailable_produces_rollback_unavailable_event(self):
        """Rollback UNAVAILABLE must produce a ROLLBACK_UNAVAILABLE event."""
        events = self._full_timeline(
            _allow_action(),
            rollback_evidence={"rollback_explicitly_unavailable": True}
        )
        types  = [e["event_type"] for e in events]
        assert "ROLLBACK_UNAVAILABLE" in types, (
            f"Expected ROLLBACK_UNAVAILABLE event, got: {types}"
        )
        print("PASS  test_rollback_unavailable_produces_rollback_unavailable_event")

    def test_ready_for_execution_event_added_when_supplied(self):
        """READY_FOR_EXECUTION event appears only when final_status supplies it."""
        events_with    = self._full_timeline(_allow_action(),
                                             final_status="READY_FOR_EXECUTION")
        events_without = self._full_timeline(_allow_action(),
                                             final_status=None)
        types_with    = [e["event_type"] for e in events_with]
        types_without = [e["event_type"] for e in events_without]
        assert "READY_FOR_EXECUTION" in types_with,    "Expected event when final_status supplied"
        assert "READY_FOR_EXECUTION" not in types_without, "Should NOT appear when not supplied"
        print("PASS  test_ready_for_execution_event_added_when_supplied")

    def test_each_event_has_required_fields(self):
        """Every event must have seq, event_type, action_summary,
        decision_or_status."""
        events = self._full_timeline(_deploy_action(),
                                     approval_decision="approved",
                                     rollback_evidence={"deployment_rollback": True},
                                     final_status="READY_FOR_EXECUTION")
        for ev in events:
            for field in ("seq", "event_type", "action_summary",
                          "decision_or_status"):
                assert field in ev and ev[field] is not None, (
                    f"Event missing or null field '{field}': {ev}"
                )
        print("PASS  test_each_event_has_required_fields")

    def test_extra_events_are_appended(self):
        """Extra caller-supplied events must be appended after built-in events."""
        extra = [{
            "event_type":         "CUSTOM_AUDIT",
            "action_summary":     "custom note",
            "decision_or_status": "noted",
            "policy_id":          None,
            "evidence_ref":       None,
            "notes":              "Custom audit entry",
        }]
        events = build_timeline(
            action       = _allow_action(),
            eval_result  = evaluate_action(_allow_action()),
            extra_events = extra,
        )
        last  = events[-1]
        types = [e["event_type"] for e in events]
        assert "CUSTOM_AUDIT" in types
        assert last["event_type"] == "CUSTOM_AUDIT"
        assert last["seq"] == len(events)
        print("PASS  test_extra_events_are_appended")

    def test_no_fabricated_events_for_absent_components(self):
        """When optional components are absent, their events must not appear."""
        events = build_timeline(
            action      = _deploy_action(),
            eval_result = evaluate_action(_deploy_action()),
            # No evidence, blast_radius, safer_plan, attack_suite,
            # gate_result, approval_record, rollback_result
        )
        types = [e["event_type"] for e in events]
        for absent_type in ("ANALYZED", "SAFER_PLAN_CREATED",
                            "SECURITY_TESTS_GENERATED", "TESTS_VERIFIED",
                            "TESTS_FAILED", "APPROVAL_REQUESTED",
                            "APPROVED", "ROLLBACK_VERIFIED"):
            assert absent_type not in types, (
                f"Event {absent_type} should not appear when component absent"
            )
        print("PASS  test_no_fabricated_events_for_absent_components")


# ===========================================================================
# Direct runner
# ===========================================================================

if __name__ == "__main__":
    test_classes = [
        TestTrustReceiptContent,
        TestFinalStatus,
        TestTimeline,
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
