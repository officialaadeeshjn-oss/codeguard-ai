"""
engine/test_phase5.py
---------------------
Automated tests for Phase 5 components:
  - approval.create_approval_record()
  - approval.decide_approval()
  - rollback.verify_rollback()
  - audit_event.build_audit_event()

Run with:
    python -m pytest engine/test_phase5.py -v
or:
    python engine/test_phase5.py

These tests do NOT modify or rely on earlier Phase 2/3/4 tests.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evaluator   import evaluate_action
from approval    import create_approval_record, decide_approval
from rollback    import verify_rollback
from audit_event import build_audit_event


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _allow_action():
    return {"tool": "read_file", "file_path": "src/utils.py"}

def _approval_required_action():
    return {"tool": "terminal", "command": "deploy to production"}

def _block_action():
    return {"tool": "terminal", "command": "DROP TABLE users;"}

def _eval(action):
    return evaluate_action(action)


# ===========================================================================
# SECTION A — Approval: create_approval_record
# ===========================================================================

class TestApprovalRecord:

    def test_allow_does_not_require_approval(self):
        """ALLOW decision → status is 'not_required'."""
        action = _allow_action()
        record = create_approval_record(action, _eval(action))
        assert record["status"] == "not_required", (
            f"Expected 'not_required' for ALLOW, got '{record['status']}'"
        )
        print("PASS  test_allow_does_not_require_approval")

    def test_approval_required_starts_as_pending(self):
        """APPROVAL_REQUIRED decision → status starts as 'pending'."""
        action = _approval_required_action()
        record = create_approval_record(action, _eval(action))
        assert record["status"] == "pending", (
            f"Expected 'pending' for APPROVAL_REQUIRED, got '{record['status']}'"
        )
        print("PASS  test_approval_required_starts_as_pending")

    def test_block_creates_blocked_record(self):
        """BLOCK decision → status is 'blocked'."""
        action = _block_action()
        record = create_approval_record(action, _eval(action))
        assert record["status"] == "blocked", (
            f"Expected 'blocked' for BLOCK, got '{record['status']}'"
        )
        print("PASS  test_block_creates_blocked_record")

    def test_record_contains_required_keys(self):
        """Approval record must contain all required top-level keys."""
        action = _approval_required_action()
        record = create_approval_record(action, _eval(action))
        for key in ("action", "decision", "policy_ids", "reasons",
                    "status", "approver", "timestamp", "notes"):
            assert key in record, f"Missing key in approval record: {key}"
        print("PASS  test_record_contains_required_keys")

    def test_approver_and_timestamp_are_none_on_creation(self):
        """approver and timestamp must both be None on a fresh record."""
        action = _approval_required_action()
        record = create_approval_record(action, _eval(action))
        assert record["approver"]  is None
        assert record["timestamp"] is None
        print("PASS  test_approver_and_timestamp_are_none_on_creation")

    def test_policy_ids_populated_for_matched_decision(self):
        """policy_ids must list the matched policy IDs."""
        action = _block_action()
        record = create_approval_record(action, _eval(action))
        assert "DATA-001" in record["policy_ids"], (
            f"Expected DATA-001 in policy_ids: {record['policy_ids']}"
        )
        print("PASS  test_policy_ids_populated_for_matched_decision")

    def test_warn_does_not_require_approval(self):
        """WARN decision (if it ever occurs) → status is 'not_required'."""
        # Fabricate a minimal WARN eval_result (the evaluator never produces
        # WARN currently, but the approval component must handle it correctly)
        fake_eval = {"decision": "WARN", "matched_policies": []}
        record = create_approval_record(_allow_action(), fake_eval)
        assert record["status"] == "not_required"
        print("PASS  test_warn_does_not_require_approval")


# ===========================================================================
# SECTION B — Approval: decide_approval
# ===========================================================================

class TestDecideApproval:

    def _pending_record(self):
        action = _approval_required_action()
        return create_approval_record(action, _eval(action))

    def test_approval_required_can_be_approved(self):
        """A pending record can be set to 'approved'."""
        record  = self._pending_record()
        updated = decide_approval(record, "approved",
                                  approver="alice@example.com",
                                  timestamp="2024-01-15T10:00:00Z")
        assert updated["status"]    == "approved"
        assert updated["approver"]  == "alice@example.com"
        assert updated["timestamp"] == "2024-01-15T10:00:00Z"
        print("PASS  test_approval_required_can_be_approved")

    def test_approval_required_can_be_rejected(self):
        """A pending record can be set to 'rejected'."""
        record  = self._pending_record()
        updated = decide_approval(record, "rejected",
                                  approver="bob@example.com")
        assert updated["status"]   == "rejected"
        assert updated["approver"] == "bob@example.com"
        print("PASS  test_approval_required_can_be_rejected")

    def test_block_cannot_be_approved(self):
        """A 'blocked' record must raise ValueError on any decide_approval call."""
        action = _block_action()
        record = create_approval_record(action, _eval(action))
        assert record["status"] == "blocked"
        with pytest.raises(ValueError):
            decide_approval(record, "approved", approver="hacker@evil.com")
        print("PASS  test_block_cannot_be_approved")

    def test_not_required_cannot_be_decided(self):
        """A 'not_required' record cannot be changed by decide_approval."""
        action = _allow_action()
        record = create_approval_record(action, _eval(action))
        assert record["status"] == "not_required"
        with pytest.raises(ValueError):
            decide_approval(record, "approved", approver="alice@example.com")
        print("PASS  test_not_required_cannot_be_decided")

    def test_already_approved_is_immutable(self):
        """An already-approved record cannot be re-decided."""
        record  = self._pending_record()
        approved = decide_approval(record, "approved", approver="alice@example.com")
        with pytest.raises(ValueError):
            decide_approval(approved, "rejected", approver="bob@example.com")
        print("PASS  test_already_approved_is_immutable")

    def test_already_rejected_is_immutable(self):
        """An already-rejected record cannot be re-decided."""
        record   = self._pending_record()
        rejected = decide_approval(record, "rejected", approver="bob@example.com")
        with pytest.raises(ValueError):
            decide_approval(rejected, "approved", approver="alice@example.com")
        print("PASS  test_already_rejected_is_immutable")

    def test_invalid_decision_raises_value_error(self):
        """An unrecognised decision value must raise ValueError."""
        record = self._pending_record()
        with pytest.raises(ValueError):
            decide_approval(record, "maybe", approver="alice@example.com")
        print("PASS  test_invalid_decision_raises_value_error")

    def test_empty_approver_raises_value_error(self):
        """An empty approver string must raise ValueError."""
        record = self._pending_record()
        with pytest.raises(ValueError):
            decide_approval(record, "approved", approver="")
        print("PASS  test_empty_approver_raises_value_error")

    def test_decide_does_not_mutate_original_record(self):
        """decide_approval must return a new dict and not mutate the input."""
        record  = self._pending_record()
        original_status = record["status"]
        decide_approval(record, "approved", approver="alice@example.com")
        assert record["status"] == original_status, (
            "decide_approval must not mutate the original record"
        )
        print("PASS  test_decide_does_not_mutate_original_record")


# ===========================================================================
# SECTION C — Rollback Verification
# ===========================================================================

class TestRollback:

    def test_returns_required_keys(self):
        """verify_rollback must return all required keys."""
        result = verify_rollback({})
        for key in ("verdict", "positive_signals", "blocker",
                    "notes", "raw_evidence"):
            assert key in result, f"Missing key: {key}"
        print("PASS  test_returns_required_keys")

    def test_not_verified_when_no_evidence(self):
        """Empty evidence must produce NOT_VERIFIED."""
        result = verify_rollback({})
        assert result["verdict"] == "NOT_VERIFIED"
        assert result["positive_signals"] == []
        assert result["blocker"] is False
        print("PASS  test_not_verified_when_no_evidence")

    def test_none_evidence_treated_as_empty(self):
        """None evidence must behave like an empty dict."""
        result = verify_rollback(None)
        assert result["verdict"] == "NOT_VERIFIED"
        print("PASS  test_none_evidence_treated_as_empty")

    def test_available_when_backup_supplied(self):
        """backup_available=True must produce AVAILABLE."""
        result = verify_rollback({"backup_available": True})
        assert result["verdict"] == "AVAILABLE"
        assert "backup_available" in result["positive_signals"]
        print("PASS  test_available_when_backup_supplied")

    def test_available_when_reversible_file_change(self):
        """reversible_file_change=True must produce AVAILABLE."""
        result = verify_rollback({"reversible_file_change": True})
        assert result["verdict"] == "AVAILABLE"
        print("PASS  test_available_when_reversible_file_change")

    def test_available_when_migration_rollback(self):
        """migration_rollback=True must produce AVAILABLE."""
        result = verify_rollback({"migration_rollback": True})
        assert result["verdict"] == "AVAILABLE"
        print("PASS  test_available_when_migration_rollback")

    def test_available_when_deployment_rollback(self):
        """deployment_rollback=True must produce AVAILABLE."""
        result = verify_rollback({"deployment_rollback": True})
        assert result["verdict"] == "AVAILABLE"
        print("PASS  test_available_when_deployment_rollback")

    def test_unavailable_when_explicit_blocker(self):
        """rollback_explicitly_unavailable=True must produce UNAVAILABLE."""
        result = verify_rollback({"rollback_explicitly_unavailable": True})
        assert result["verdict"] == "UNAVAILABLE"
        assert result["blocker"] is True
        print("PASS  test_unavailable_when_explicit_blocker")

    def test_blocker_overrides_positive_evidence(self):
        """Explicit blocker takes precedence over any positive evidence."""
        result = verify_rollback({
            "backup_available":              True,
            "rollback_explicitly_unavailable": True,
        })
        assert result["verdict"] == "UNAVAILABLE", (
            "Explicit blocker must override backup_available"
        )
        print("PASS  test_blocker_overrides_positive_evidence")

    def test_false_positive_keys_do_not_trigger_available(self):
        """Positive keys set to False must not produce AVAILABLE."""
        result = verify_rollback({"backup_available": False,
                                  "reversible_file_change": False})
        assert result["verdict"] == "NOT_VERIFIED"
        print("PASS  test_false_positive_keys_do_not_trigger_available")

    def test_notes_is_non_empty_string(self):
        """notes must always be a non-empty string."""
        for ev in ({}, {"backup_available": True},
                   {"rollback_explicitly_unavailable": True}):
            result = verify_rollback(ev)
            assert isinstance(result["notes"], str) and result["notes"]
        print("PASS  test_notes_is_non_empty_string")

    def test_raw_evidence_preserved(self):
        """raw_evidence must equal the input dict."""
        ev     = {"backup_available": True, "notes": "nightly backup confirmed"}
        result = verify_rollback(ev)
        assert result["raw_evidence"] == ev
        print("PASS  test_raw_evidence_preserved")


# ===========================================================================
# SECTION D — Audit Event
# ===========================================================================

class TestAuditEvent:

    def _make_event(self, action, approval_decision=None,
                    approver="test-approver", rollback_evidence=None):
        """Helper: build a full audit event for a given action."""
        eval_result = evaluate_action(action)
        rec         = create_approval_record(action, eval_result)
        if approval_decision and rec["status"] == "pending":
            rec = decide_approval(rec, approval_decision, approver=approver)
        rollback = verify_rollback(rollback_evidence or {})
        return build_audit_event(action, eval_result, rec, rollback)

    def test_returns_required_keys(self):
        """build_audit_event must return all required top-level keys."""
        event = self._make_event(_allow_action())
        for key in ("action", "policy_decision", "matched_policy_ids",
                    "approval_status", "approver", "approval_timestamp",
                    "rollback_verdict", "rollback_signals",
                    "status", "summary"):
            assert key in event, f"Missing key in audit event: {key}"
        print("PASS  test_returns_required_keys")

    def test_allow_action_is_permitted(self):
        """An ALLOW action with no rollback evidence → status PERMITTED."""
        event = self._make_event(_allow_action())
        assert event["policy_decision"] == "ALLOW"
        assert event["status"] == "PERMITTED"
        print("PASS  test_allow_action_is_permitted")

    def test_block_action_is_blocked(self):
        """A BLOCK decision must produce status BLOCKED in the audit event."""
        event = self._make_event(_block_action())
        assert event["status"] == "BLOCKED"
        assert event["policy_decision"] == "BLOCK"
        print("PASS  test_block_action_is_blocked")

    def test_pending_approval_status_in_event(self):
        """An unapproved APPROVAL_REQUIRED action → status PENDING_APPROVAL."""
        action      = _approval_required_action()
        eval_result = evaluate_action(action)
        rec         = create_approval_record(action, eval_result)
        # do NOT call decide_approval — leave it pending
        rollback    = verify_rollback({})
        event       = build_audit_event(action, eval_result, rec, rollback)
        assert event["status"] == "PENDING_APPROVAL", (
            f"Expected PENDING_APPROVAL, got {event['status']}"
        )
        assert event["approval_status"] == "pending"
        print("PASS  test_pending_approval_status_in_event")

    def test_approved_action_is_permitted(self):
        """An approved APPROVAL_REQUIRED action with rollback → PERMITTED."""
        event = self._make_event(
            _approval_required_action(),
            approval_decision="approved",
            rollback_evidence={"deployment_rollback": True},
        )
        assert event["status"] == "PERMITTED"
        assert event["approval_status"] == "approved"
        assert event["rollback_verdict"] == "AVAILABLE"
        print("PASS  test_approved_action_is_permitted")

    def test_rejected_action_is_rejected(self):
        """A rejected APPROVAL_REQUIRED action → status REJECTED."""
        event = self._make_event(
            _approval_required_action(),
            approval_decision="rejected",
            approver="security-reviewer",
        )
        assert event["status"] == "REJECTED"
        assert event["approval_status"] == "rejected"
        print("PASS  test_rejected_action_is_rejected")

    def test_permitted_no_rollback_when_rollback_unavailable(self):
        """ALLOW decision + rollback explicitly unavailable → PERMITTED_NO_ROLLBACK."""
        event = self._make_event(
            _allow_action(),
            rollback_evidence={"rollback_explicitly_unavailable": True},
        )
        assert event["status"] == "PERMITTED_NO_ROLLBACK"
        assert event["rollback_verdict"] == "UNAVAILABLE"
        print("PASS  test_permitted_no_rollback_when_rollback_unavailable")

    def test_approved_deploy_no_rollback_is_permitted_no_rollback(self):
        """Approved deploy + rollback explicitly unavailable → PERMITTED_NO_ROLLBACK."""
        event = self._make_event(
            _approval_required_action(),
            approval_decision="approved",
            rollback_evidence={"rollback_explicitly_unavailable": True},
        )
        assert event["status"] == "PERMITTED_NO_ROLLBACK"
        print("PASS  test_approved_deploy_no_rollback_is_permitted_no_rollback")

    def test_summary_is_non_empty_string(self):
        """summary must always be a non-empty string."""
        for action in (_allow_action(), _block_action(),
                       _approval_required_action()):
            event = self._make_event(action)
            assert isinstance(event["summary"], str) and event["summary"], (
                f"summary is empty for action {action}"
            )
        print("PASS  test_summary_is_non_empty_string")

    def test_matched_policy_ids_forwarded(self):
        """matched_policy_ids in the event must match the evaluator output."""
        action      = _block_action()
        eval_result = evaluate_action(action)
        rec         = create_approval_record(action, eval_result)
        rollback    = verify_rollback({})
        event       = build_audit_event(action, eval_result, rec, rollback)
        expected_ids = [m["policy_id"] for m in eval_result["matched_policies"]]
        assert event["matched_policy_ids"] == expected_ids
        print("PASS  test_matched_policy_ids_forwarded")


# ===========================================================================
# Direct runner
# ===========================================================================

if __name__ == "__main__":
    test_classes = [
        TestApprovalRecord,
        TestDecideApproval,
        TestRollback,
        TestAuditEvent,
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
