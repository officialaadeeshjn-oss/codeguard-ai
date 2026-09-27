"""
engine/test_gate.py
-------------------
Test-gate component for CodeGuard AI.

Evaluates a set of generated security test cases against actual test results
and returns an overall gate verdict: PASS, FAIL, or NOT_RUN.

Design principles
-----------------
- Honest: the gate NEVER fabricates results.
- Deterministic: same inputs → same verdict.
- Three-state: clearly distinguishes PASS, FAIL, and NOT_RUN.
- The gate accepts only explicit results — absence of a result is NOT_RUN.

Concepts
--------
  generated tests  : list of test-case dicts produced by attack_tests.py
  actual results   : dict mapping test-case ID → "pass" | "fail"
                     (tests absent from this dict are treated as NOT_RUN)

Gate verdict rules (applied in order)
--------------------------------------
  1. If any test has result "fail"    → overall verdict is FAIL
  2. If any test has no result        → overall verdict is NOT_RUN
     (unless all non-failed tests have an explicit "pass")
  3. If every test has result "pass"  → overall verdict is PASS
  4. If there are no test cases       → overall verdict is NOT_RUN

Individual test status
----------------------
  "pass"    – actual_results[id] == "pass"
  "fail"    – actual_results[id] == "fail"
  "not_run" – id absent from actual_results

Usage:
    from engine.test_gate import evaluate_gate

    # Simulate: all tests generated, none run yet
    gate = evaluate_gate(test_suite, actual_results={})
    # gate["verdict"] == "NOT_RUN"

    # Simulate: all tests passed
    results = {tc["id"]: "pass" for tc in test_suite["test_cases"]}
    gate = evaluate_gate(test_suite, actual_results=results)
    # gate["verdict"] == "PASS"

    # Simulate: one test failed
    results["AUTH-002-T2"] = "fail"
    gate = evaluate_gate(test_suite, actual_results=results)
    # gate["verdict"] == "FAIL"
"""

# Valid result values (case-insensitive on input)
_VALID_RESULTS = {"pass", "fail"}


def evaluate_gate(test_suite: dict, actual_results: dict = None) -> dict:
    """
    Evaluate generated security test cases against actual results.

    Parameters
    ----------
    test_suite      : dict returned by generate_attack_tests()
    actual_results  : dict mapping test-case ID (str) → "pass" | "fail"
                      Omit a test ID to indicate it has not been run.
                      Pass an empty dict (or None) to indicate nothing has run.

    Returns
    -------
    dict with keys:
        verdict         – "PASS" | "FAIL" | "NOT_RUN"
        total           – total number of test cases
        passed          – count of tests with result "pass"
        failed          – count of tests with result "fail"
        not_run         – count of tests with no result
        test_results    – list of per-test dicts:
                            {id, name, policy_id, category, status}
                            status is "pass" | "fail" | "not_run"
        summary         – human-readable one-line verdict explanation
    """
    if actual_results is None:
        actual_results = {}

    # Normalise keys to lower-case for robust matching
    normalised = {k: v.lower() for k, v in actual_results.items()
                  if isinstance(v, str) and v.lower() in _VALID_RESULTS}

    test_cases = test_suite.get("test_cases", [])

    per_test   = []
    n_pass     = 0
    n_fail     = 0
    n_not_run  = 0

    for tc in test_cases:
        tc_id   = tc.get("id", "")
        raw     = normalised.get(tc_id)

        if raw == "pass":
            status = "pass"
            n_pass += 1
        elif raw == "fail":
            status = "fail"
            n_fail += 1
        else:
            status = "not_run"
            n_not_run += 1

        per_test.append({
            "id":        tc_id,
            "name":      tc.get("name", ""),
            "policy_id": tc.get("policy_id", ""),
            "category":  tc.get("category", ""),
            "status":    status,
        })

    # Overall verdict
    total = len(test_cases)

    if total == 0:
        verdict = "NOT_RUN"
        summary = "No test cases were generated; nothing to evaluate."
    elif n_fail > 0:
        verdict = "FAIL"
        summary = (
            f"{n_fail} test(s) FAILED, {n_pass} passed, "
            f"{n_not_run} not run — gate is FAIL."
        )
    elif n_not_run > 0:
        verdict = "NOT_RUN"
        summary = (
            f"{n_not_run} test(s) have not been executed yet "
            f"({n_pass} passed so far) — gate is NOT_RUN."
        )
    else:
        # All tests have an explicit "pass" result
        verdict = "PASS"
        summary = f"All {n_pass} test(s) passed — gate is PASS."

    return {
        "verdict":      verdict,
        "total":        total,
        "passed":       n_pass,
        "failed":       n_fail,
        "not_run":      n_not_run,
        "test_results": per_test,
        "summary":      summary,
    }


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from evaluator import evaluate_action
    from attack_tests import generate_attack_tests

    action = {
        "tool": "edit_file",
        "command": "store reset token plaintext in database",
    }
    result   = evaluate_action(action)
    suite    = generate_attack_tests(action, result)

    print("=== NOT_RUN (no results provided) ===")
    gate = evaluate_gate(suite, actual_results={})
    print(json.dumps(gate, indent=2))

    print("\n=== PASS (all tests passed) ===")
    all_pass = {tc["id"]: "pass" for tc in suite["test_cases"]}
    gate = evaluate_gate(suite, actual_results=all_pass)
    print(json.dumps(gate, indent=2))

    print("\n=== FAIL (one test failed) ===")
    one_fail = dict(all_pass)
    one_fail[suite["test_cases"][0]["id"]] = "fail"
    gate = evaluate_gate(suite, actual_results=one_fail)
    print(json.dumps(gate, indent=2))
