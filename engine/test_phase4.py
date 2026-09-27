"""
engine/test_phase4.py
---------------------
Automated tests for Phase 4 components:
  - safer_plan.generate_safer_plan()
  - attack_tests.generate_attack_tests()
  - test_gate.evaluate_gate()

Run with:
    python -m pytest engine/test_phase4.py -v
or:
    python engine/test_phase4.py

These tests do NOT modify the evaluator or the existing Phase 2/3 tests.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evaluator    import evaluate_action
from safer_plan   import generate_safer_plan
from attack_tests import generate_attack_tests
from test_gate    import evaluate_gate


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _otp_action():
    """Standard OTP/reset-token action used across multiple tests."""
    return {
        "tool": "edit_file",
        "command": "store reset token plaintext in database",
    }


def _otp_eval():
    return evaluate_action(_otp_action())


# ===========================================================================
# SECTION A — Safer Plan Generator
# ===========================================================================

class TestSaferPlan:

    def test_returns_required_keys(self):
        """generate_safer_plan must return all required top-level keys."""
        plan = generate_safer_plan(_otp_action(), _otp_eval())
        required = {
            "original_action", "decision", "matched_policy_ids",
            "why_unsafe", "safer_steps", "affected_components",
            "verification_steps", "disclaimer",
        }
        missing = required - set(plan.keys())
        assert not missing, f"Missing keys: {missing}"
        print("PASS  test_returns_required_keys")

    def test_plan_generated_for_blocked_action(self):
        """A BLOCK decision must produce a non-empty plan (not just ALLOW info)."""
        action = {"tool": "terminal", "command": "DROP TABLE users;"}
        result = evaluate_action(action)
        plan   = generate_safer_plan(action, result)
        assert plan["decision"] == "BLOCK", (
            f"Expected BLOCK, got {plan['decision']}"
        )
        assert len(plan["safer_steps"]) > 0, "Expected safer_steps to be non-empty"
        print("PASS  test_plan_generated_for_blocked_action")

    def test_plan_contains_matched_policy_id(self):
        """The safer plan must include the policy ID that triggered the block."""
        action = {"tool": "terminal", "command": "DROP TABLE users;"}
        result = evaluate_action(action)
        plan   = generate_safer_plan(action, result)
        assert "DATA-001" in plan["matched_policy_ids"], (
            f"Expected DATA-001 in matched_policy_ids: {plan['matched_policy_ids']}"
        )
        print("PASS  test_plan_contains_matched_policy_id")

    def test_plan_contains_reason_for_otp_action(self):
        """The OTP/reset-token plan must reference AUTH-002 and plaintext storage."""
        plan = generate_safer_plan(_otp_action(), _otp_eval())
        assert "AUTH-002" in plan["matched_policy_ids"], (
            f"Expected AUTH-002 in matched_policy_ids: {plan['matched_policy_ids']}"
        )
        # why_unsafe should mention tokens/plaintext
        combined_why = " ".join(plan["why_unsafe"]).lower()
        assert "token" in combined_why or "plaintext" in combined_why, (
            "Expected why_unsafe to mention 'token' or 'plaintext' for AUTH-002"
        )
        print("PASS  test_plan_contains_reason_for_otp_action")

    def test_safer_steps_are_list_of_strings(self):
        """safer_steps must be a list of non-empty strings."""
        plan = generate_safer_plan(_otp_action(), _otp_eval())
        assert isinstance(plan["safer_steps"], list)
        assert all(isinstance(s, str) and s for s in plan["safer_steps"]), (
            "All safer_steps must be non-empty strings"
        )
        print("PASS  test_safer_steps_are_list_of_strings")

    def test_verification_steps_are_list_of_strings(self):
        """verification_steps must be a list of non-empty strings."""
        plan = generate_safer_plan(_otp_action(), _otp_eval())
        assert isinstance(plan["verification_steps"], list)
        assert all(isinstance(s, str) and s for s in plan["verification_steps"]), (
            "All verification_steps must be non-empty strings"
        )
        print("PASS  test_verification_steps_are_list_of_strings")

    def test_allow_action_produces_informational_plan(self):
        """An ALLOW decision must still produce a valid (informational) plan."""
        action = {"tool": "read_file", "file_path": "src/utils.py"}
        result = evaluate_action(action)
        plan   = generate_safer_plan(action, result)
        assert plan["decision"] == "ALLOW"
        assert isinstance(plan["safer_steps"], list)
        print("PASS  test_allow_action_produces_informational_plan")

    def test_approval_required_plan_includes_deploy001(self):
        """A production-deployment action must produce a plan with DEPLOY-001."""
        action = {"tool": "terminal", "command": "deploy to production"}
        result = evaluate_action(action)
        plan   = generate_safer_plan(action, result)
        assert "DEPLOY-001" in plan["matched_policy_ids"], (
            f"Expected DEPLOY-001 in matched_policy_ids: {plan['matched_policy_ids']}"
        )
        print("PASS  test_approval_required_plan_includes_deploy001")

    def test_plan_with_evidence_enriches_affected_components(self):
        """Passing an evidence dict should populate affected_components."""
        from evidence import extract_evidence
        action = {
            "tool": "edit_file",
            "file_path": "services/reset.py",
            "command": "store reset token plaintext in database",
        }
        result  = evaluate_action(action)
        ev      = extract_evidence(action, result)
        plan    = generate_safer_plan(action, result, evidence=ev)
        # services/reset.py must appear in affected_components
        assert "services/reset.py" in plan["affected_components"], (
            f"Expected services/reset.py in affected_components: "
            f"{plan['affected_components']}"
        )
        print("PASS  test_plan_with_evidence_enriches_affected_components")

    def test_disclaimer_is_present(self):
        """The disclaimer key must be a non-empty string."""
        plan = generate_safer_plan(_otp_action(), _otp_eval())
        assert isinstance(plan["disclaimer"], str) and plan["disclaimer"]
        print("PASS  test_disclaimer_is_present")


# ===========================================================================
# SECTION B — Attack-Path Test Generator
# ===========================================================================

class TestAttackTests:

    def test_returns_required_keys(self):
        """generate_attack_tests must return all required keys."""
        suite = generate_attack_tests(_otp_action(), _otp_eval())
        for key in ("matched_policy_ids", "test_cases", "total", "disclaimer"):
            assert key in suite, f"Missing key: {key}"
        print("PASS  test_returns_required_keys")

    def test_otp_action_generates_test_cases(self):
        """An OTP/reset-token action must produce at least one test case."""
        suite = generate_attack_tests(_otp_action(), _otp_eval())
        assert suite["total"] > 0, "Expected at least one generated test case"
        assert len(suite["test_cases"]) == suite["total"]
        print("PASS  test_otp_action_generates_test_cases")

    def test_otp_tests_cover_auth002_scenarios(self):
        """
        The test cases for an OTP action must cover the key attack scenarios:
        expired, incorrect, reused, unauthorised, plaintext storage.
        """
        suite     = generate_attack_tests(_otp_action(), _otp_eval())
        test_ids  = {tc["id"] for tc in suite["test_cases"]}
        expected  = {
            "AUTH-002-T1",  # expired token
            "AUTH-002-T2",  # incorrect token
            "AUTH-002-T3",  # reused token
            "AUTH-002-T4",  # unauthorised reset
            "AUTH-002-T5",  # plaintext storage
        }
        missing = expected - test_ids
        assert not missing, (
            f"Expected OTP test IDs not generated: {missing}"
        )
        print("PASS  test_otp_tests_cover_auth002_scenarios")

    def test_auth_bypass_generates_auth001_tests(self):
        """An authentication-bypass action must produce AUTH-001 test cases."""
        action = {
            "tool": "edit_file",
            "code": "// bypass authentication for internal routes",
        }
        result = evaluate_action(action)
        suite  = generate_attack_tests(action, result)
        test_ids = {tc["id"] for tc in suite["test_cases"]}
        assert "AUTH-001-T1" in test_ids, (
            f"Expected AUTH-001-T1 in generated tests: {test_ids}"
        )
        print("PASS  test_auth_bypass_generates_auth001_tests")

    def test_data_destruction_generates_data001_tests(self):
        """A DROP TABLE action must produce DATA-001 test cases."""
        action = {"tool": "terminal", "command": "DROP TABLE users;"}
        result = evaluate_action(action)
        suite  = generate_attack_tests(action, result)
        test_ids = {tc["id"] for tc in suite["test_cases"]}
        assert "DATA-001-T1" in test_ids, (
            f"Expected DATA-001-T1 in generated tests: {test_ids}"
        )
        print("PASS  test_data_destruction_generates_data001_tests")

    def test_each_test_case_has_required_fields(self):
        """Each test case dict must contain id, name, description, category, policy_id."""
        suite = generate_attack_tests(_otp_action(), _otp_eval())
        for tc in suite["test_cases"]:
            for field in ("id", "name", "description", "category", "policy_id"):
                assert field in tc and tc[field], (
                    f"Test case missing or empty field '{field}': {tc}"
                )
        print("PASS  test_each_test_case_has_required_fields")

    def test_safe_action_produces_no_test_cases(self):
        """A safe (ALLOW) action must produce zero test cases."""
        action = {"tool": "read_file", "file_path": "src/utils.py"}
        result = evaluate_action(action)
        suite  = generate_attack_tests(action, result)
        assert suite["total"] == 0, (
            f"Expected 0 test cases for safe action, got {suite['total']}"
        )
        print("PASS  test_safe_action_produces_no_test_cases")

    def test_disclaimer_is_present_and_honest(self):
        """The disclaimer must state that tests have NOT been executed."""
        suite = generate_attack_tests(_otp_action(), _otp_eval())
        assert "NOT" in suite["disclaimer"].upper() or \
               "not" in suite["disclaimer"], (
            "Disclaimer must clarify tests have not been executed"
        )
        print("PASS  test_disclaimer_is_present_and_honest")


# ===========================================================================
# SECTION C — Test Gate
# ===========================================================================

class TestGate:

    def _otp_suite(self):
        return generate_attack_tests(_otp_action(), _otp_eval())

    def test_returns_required_keys(self):
        """evaluate_gate must return all required keys."""
        gate = evaluate_gate(self._otp_suite(), actual_results={})
        for key in ("verdict", "total", "passed", "failed",
                    "not_run", "test_results", "summary"):
            assert key in gate, f"Missing key in gate result: {key}"
        print("PASS  test_returns_required_keys")

    def test_not_run_when_no_results_provided(self):
        """Gate must return NOT_RUN when no actual results are provided."""
        gate = evaluate_gate(self._otp_suite(), actual_results={})
        assert gate["verdict"] == "NOT_RUN", (
            f"Expected NOT_RUN but got {gate['verdict']}"
        )
        assert gate["not_run"] == gate["total"]
        assert gate["passed"] == 0
        assert gate["failed"] == 0
        print("PASS  test_not_run_when_no_results_provided")

    def test_pass_when_all_tests_pass(self):
        """Gate must return PASS when every test has result 'pass'."""
        suite = self._otp_suite()
        all_pass = {tc["id"]: "pass" for tc in suite["test_cases"]}
        gate = evaluate_gate(suite, actual_results=all_pass)
        assert gate["verdict"] == "PASS", (
            f"Expected PASS but got {gate['verdict']}"
        )
        assert gate["passed"] == gate["total"]
        assert gate["failed"] == 0
        assert gate["not_run"] == 0
        print("PASS  test_pass_when_all_tests_pass")

    def test_fail_when_one_test_fails(self):
        """Gate must return FAIL when at least one test has result 'fail'."""
        suite    = self._otp_suite()
        results  = {tc["id"]: "pass" for tc in suite["test_cases"]}
        # Flip the first test to fail
        first_id = suite["test_cases"][0]["id"]
        results[first_id] = "fail"
        gate = evaluate_gate(suite, actual_results=results)
        assert gate["verdict"] == "FAIL", (
            f"Expected FAIL but got {gate['verdict']}"
        )
        assert gate["failed"] >= 1
        print("PASS  test_fail_when_one_test_fails")

    def test_not_run_when_only_partial_results(self):
        """Gate returns NOT_RUN when some tests passed but others have no result."""
        suite   = self._otp_suite()
        partial = {suite["test_cases"][0]["id"]: "pass"}  # only first test reported
        gate    = evaluate_gate(suite, actual_results=partial)
        assert gate["verdict"] == "NOT_RUN", (
            f"Expected NOT_RUN with partial results but got {gate['verdict']}"
        )
        assert gate["not_run"] > 0
        print("PASS  test_not_run_when_only_partial_results")

    def test_individual_test_statuses_are_correct(self):
        """Each per-test status in test_results must reflect the actual result."""
        suite    = self._otp_suite()
        results  = {}
        ids      = [tc["id"] for tc in suite["test_cases"]]
        if len(ids) >= 2:
            results[ids[0]] = "pass"
            results[ids[1]] = "fail"
            # ids[2:] left unset → not_run
        gate = evaluate_gate(suite, actual_results=results)
        status_map = {tr["id"]: tr["status"] for tr in gate["test_results"]}
        if len(ids) >= 1:
            assert status_map[ids[0]] == "pass"
        if len(ids) >= 2:
            assert status_map[ids[1]] == "fail"
        if len(ids) >= 3:
            assert status_map[ids[2]] == "not_run"
        print("PASS  test_individual_test_statuses_are_correct")

    def test_none_actual_results_treated_as_empty(self):
        """Passing None for actual_results must behave like an empty dict."""
        gate = evaluate_gate(self._otp_suite(), actual_results=None)
        assert gate["verdict"] == "NOT_RUN"
        print("PASS  test_none_actual_results_treated_as_empty")

    def test_empty_suite_returns_not_run(self):
        """A suite with no test cases must return NOT_RUN."""
        empty_suite = {"test_cases": [], "total": 0,
                       "matched_policy_ids": [], "disclaimer": ""}
        gate = evaluate_gate(empty_suite, actual_results={})
        assert gate["verdict"] == "NOT_RUN", (
            f"Expected NOT_RUN for empty suite, got {gate['verdict']}"
        )
        print("PASS  test_empty_suite_returns_not_run")

    def test_counts_are_internally_consistent(self):
        """passed + failed + not_run must equal total."""
        suite   = self._otp_suite()
        results = {tc["id"]: "pass" for tc in suite["test_cases"][:2]}
        gate    = evaluate_gate(suite, actual_results=results)
        assert gate["passed"] + gate["failed"] + gate["not_run"] == gate["total"], (
            "Count mismatch: passed + failed + not_run != total"
        )
        print("PASS  test_counts_are_internally_consistent")

    def test_summary_is_non_empty_string(self):
        """summary must always be a non-empty string."""
        gate = evaluate_gate(self._otp_suite(), actual_results={})
        assert isinstance(gate["summary"], str) and gate["summary"]
        print("PASS  test_summary_is_non_empty_string")


# ===========================================================================
# Direct runner
# ===========================================================================

if __name__ == "__main__":
    test_classes = [TestSaferPlan, TestAttackTests, TestGate]

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
