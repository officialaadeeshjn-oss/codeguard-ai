"""
engine/test_phase3.py
---------------------
Automated tests for Phase 3 components:
  - repo_analyzer.analyze_repo()
  - evidence.extract_evidence()
  - blast_radius.analyze_blast_radius()

Run with:
    python -m pytest engine/test_phase3.py -v
or:
    python engine/test_phase3.py

These tests do NOT modify the evaluator or its existing 7 tests.
"""

import sys
import os

# Ensure the engine directory is importable regardless of CWD.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from repo_analyzer import analyze_repo
from evidence import extract_evidence
from blast_radius import analyze_blast_radius
from evaluator import evaluate_action


# ===========================================================================
# SECTION 1 — Repository Analyzer
# ===========================================================================

class TestRepoAnalyzer:

    def test_returns_required_keys(self):
        """analyze_repo() must always return the four required top-level keys."""
        result = analyze_repo()
        assert "root" in result,       "Missing key: root"
        assert "components" in result, "Missing key: components"
        assert "summary" in result,    "Missing key: summary"
        assert "missing" in result,    "Missing key: missing"
        print("PASS  test_returns_required_keys")

    def test_root_is_string(self):
        """root must be a non-empty string (absolute path)."""
        result = analyze_repo()
        assert isinstance(result["root"], str), "root is not a string"
        assert len(result["root"]) > 0,         "root is empty"
        print("PASS  test_root_is_string")

    def test_components_is_dict(self):
        """components must be a dict."""
        result = analyze_repo()
        assert isinstance(result["components"], dict), "components is not a dict"
        print("PASS  test_components_is_dict")

    def test_expected_component_labels_present(self):
        """The components dict must contain all expected labels."""
        expected_labels = {
            "frontend_entry", "backend_entry", "auth_middleware",
            "auth_routes", "user_model", "password_reset_service",
            "test_directory", "test_files", "deployment_config",
        }
        result = analyze_repo()
        actual_labels = set(result["components"].keys())
        missing_labels = expected_labels - actual_labels
        assert not missing_labels, (
            f"Components dict is missing labels: {missing_labels}"
        )
        print("PASS  test_expected_component_labels_present")

    def test_empty_repo_has_no_phantom_paths(self):
        """
        In our mostly-empty repository, most component lists must be empty.
        The one exception is test_files, which should include our own test
        files (test_evaluator.py, test_phase3.py).
        """
        result = analyze_repo()
        components = result["components"]
        # These folders/files genuinely don't exist yet — lists must be empty
        for label in ("frontend_entry", "backend_entry", "auth_middleware",
                      "auth_routes", "user_model", "password_reset_service",
                      "test_directory", "deployment_config"):
            assert components[label] == [], (
                f"Expected empty list for '{label}' in empty repo, "
                f"got {components[label]}"
            )
        print("PASS  test_empty_repo_has_no_phantom_paths")

    def test_existing_test_files_are_detected(self):
        """
        Our own test files (test_evaluator.py, test_phase3.py) live under
        engine/ and should be detected as test files by the walker.
        """
        result = analyze_repo()
        test_files = result["components"]["test_files"]
        names = [os.path.basename(f) for f in test_files]
        assert "test_evaluator.py" in names, (
            f"test_evaluator.py not found in test_files: {test_files}"
        )
        assert "test_phase3.py" in names, (
            f"test_phase3.py not found in test_files: {test_files}"
        )
        print("PASS  test_existing_test_files_are_detected")

    def test_summary_and_missing_are_lists(self):
        """summary and missing must both be lists."""
        result = analyze_repo()
        assert isinstance(result["summary"], list), "summary is not a list"
        assert isinstance(result["missing"], list), "missing is not a list"
        print("PASS  test_summary_and_missing_are_lists")

    def test_custom_root_path(self):
        """Passing a custom root that exists returns a valid result."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            result = analyze_repo(root=tmp)
            assert result["root"] == str(os.path.realpath(tmp))
            # Every component should be empty because the temp dir is bare
            for label, paths in result["components"].items():
                assert paths == [], (
                    f"Expected empty list for '{label}' in temp dir, got {paths}"
                )
        print("PASS  test_custom_root_path")


# ===========================================================================
# SECTION 2 — Evidence Extraction
# ===========================================================================

class TestEvidenceExtraction:

    def test_returns_required_keys(self):
        """extract_evidence() must return all seven required keys."""
        action = {"tool": "read_file", "file_path": "src/utils.py"}
        eval_result = evaluate_action(action)
        ev = extract_evidence(action, eval_result)
        for key in ("tool", "affected_file", "code_location",
                    "matched_policies", "final_decision",
                    "api_component", "db_component", "notes"):
            assert key in ev, f"Missing key in evidence: {key}"
        print("PASS  test_returns_required_keys")

    def test_safe_action_no_policies(self):
        """A safe action produces ALLOW with empty matched_policies."""
        action = {"tool": "read_file", "file_path": "src/utils.py"}
        eval_result = evaluate_action(action)
        ev = extract_evidence(action, eval_result)
        assert ev["final_decision"] == "ALLOW"
        assert ev["matched_policies"] == []
        print("PASS  test_safe_action_no_policies")

    def test_tool_is_extracted(self):
        """The tool name is preserved in evidence."""
        action = {"tool": "edit_file", "file_path": "auth/middleware.py",
                  "code": "// bypass authentication"}
        eval_result = evaluate_action(action)
        ev = extract_evidence(action, eval_result)
        assert ev["tool"] == "edit_file"
        print("PASS  test_tool_is_extracted")

    def test_affected_file_is_extracted(self):
        """file_path from the action is echoed in affected_file."""
        action = {"tool": "edit_file", "file_path": "auth/middleware.py",
                  "code": "// bypass authentication"}
        eval_result = evaluate_action(action)
        ev = extract_evidence(action, eval_result)
        assert ev["affected_file"] == "auth/middleware.py"
        print("PASS  test_affected_file_is_extracted")

    def test_auth_bypass_evidence_has_api_component(self):
        """An auth-bypass action must have an API component in evidence."""
        action = {
            "tool": "edit_file",
            "file_path": "auth/middleware.py",
            "code": "// bypass authentication for internal routes",
        }
        eval_result = evaluate_action(action)
        ev = extract_evidence(action, eval_result)
        assert ev["api_component"] is not None, (
            "Expected an api_component for auth-middleware file, got None"
        )
        print("PASS  test_auth_bypass_evidence_has_api_component")

    def test_matched_policies_forwarded(self):
        """matched_policies in evidence is the same list as in eval_result."""
        action = {"tool": "terminal", "command": "DROP TABLE users;"}
        eval_result = evaluate_action(action)
        ev = extract_evidence(action, eval_result)
        assert ev["matched_policies"] == eval_result["matched_policies"]
        print("PASS  test_matched_policies_forwarded")

    def test_notes_is_non_empty_list(self):
        """notes must always be a non-empty list."""
        action = {"tool": "read_file", "file_path": "src/utils.py"}
        eval_result = evaluate_action(action)
        ev = extract_evidence(action, eval_result)
        assert isinstance(ev["notes"], list)
        assert len(ev["notes"]) > 0
        print("PASS  test_notes_is_non_empty_list")

    def test_no_file_path_still_works(self):
        """extract_evidence works when the action has no file_path."""
        action = {"tool": "terminal", "command": "deploy to production"}
        eval_result = evaluate_action(action)
        ev = extract_evidence(action, eval_result)
        assert ev["affected_file"] is None
        assert ev["final_decision"] == "APPROVAL_REQUIRED"
        print("PASS  test_no_file_path_still_works")

    def test_reset_token_plaintext_evidence(self):
        """A plaintext-reset-token action must have AUTH-002 in matched_policies."""
        action = {
            "tool": "edit_file",
            "command": "store reset token plaintext in database",
        }
        eval_result = evaluate_action(action)
        ev = extract_evidence(action, eval_result)
        policy_ids = {m["policy_id"] for m in ev["matched_policies"]}
        assert "AUTH-002" in policy_ids, (
            f"Expected AUTH-002 in evidence matched_policies, got {policy_ids}"
        )
        print("PASS  test_reset_token_plaintext_evidence")


# ===========================================================================
# SECTION 3 — Blast-Radius Analyzer
# ===========================================================================

class TestBlastRadius:

    def test_returns_required_keys(self):
        """analyze_blast_radius() must return all five required keys."""
        action = {"tool": "read_file", "file_path": "src/utils.py"}
        report = analyze_blast_radius(action)
        for key in ("affected_files", "affected_api_endpoints",
                    "affected_db_components", "affected_tests",
                    "deployment_impact", "notes"):
            assert key in report, f"Missing key in blast-radius report: {key}"
        print("PASS  test_returns_required_keys")

    def test_safe_action_minimal_blast(self):
        """A benign read action should have no significant blast radius."""
        action = {"tool": "read_file", "file_path": "src/utils.py"}
        report = analyze_blast_radius(action)
        assert report["deployment_impact"] is False
        print("PASS  test_safe_action_minimal_blast")

    def test_affected_file_included(self):
        """The file_path from the action should appear in affected_files."""
        action = {
            "tool": "edit_file",
            "file_path": "services/reset.py",
            "command": "store reset token plaintext in database",
        }
        eval_result = evaluate_action(action)
        report = analyze_blast_radius(action, eval_result=eval_result)
        assert "services/reset.py" in report["affected_files"], (
            f"Expected services/reset.py in affected_files: {report['affected_files']}"
        )
        print("PASS  test_affected_file_included")

    def test_auth002_blast_includes_api(self):
        """AUTH-002 violation must produce API-endpoint entries in blast radius."""
        action = {
            "tool": "edit_file",
            "file_path": "services/reset.py",
            "command": "store reset token plaintext in database",
        }
        eval_result = evaluate_action(action)
        report = analyze_blast_radius(action, eval_result=eval_result)
        assert len(report["affected_api_endpoints"]) > 0, (
            "Expected API endpoints in blast radius for AUTH-002 action"
        )
        print("PASS  test_auth002_blast_includes_api")

    def test_auth002_blast_includes_db(self):
        """AUTH-002 violation must produce DB component entries in blast radius."""
        action = {
            "tool": "edit_file",
            "file_path": "services/reset.py",
            "command": "store reset token plaintext in database",
        }
        eval_result = evaluate_action(action)
        report = analyze_blast_radius(action, eval_result=eval_result)
        assert len(report["affected_db_components"]) > 0, (
            "Expected DB components in blast radius for AUTH-002 action"
        )
        print("PASS  test_auth002_blast_includes_db")

    def test_auth002_blast_includes_tests(self):
        """AUTH-002 violation must populate affected_tests."""
        action = {
            "tool": "edit_file",
            "file_path": "services/reset.py",
            "command": "store reset token plaintext in database",
        }
        eval_result = evaluate_action(action)
        report = analyze_blast_radius(action, eval_result=eval_result)
        assert len(report["affected_tests"]) > 0, (
            "Expected test groups in blast radius for AUTH-002 action"
        )
        print("PASS  test_auth002_blast_includes_tests")

    def test_deploy_action_sets_deployment_impact(self):
        """A production deployment action must set deployment_impact=True."""
        action = {"tool": "terminal", "command": "deploy to production"}
        eval_result = evaluate_action(action)
        report = analyze_blast_radius(action, eval_result=eval_result)
        assert report["deployment_impact"] is True, (
            "Expected deployment_impact=True for a production-deploy action"
        )
        print("PASS  test_deploy_action_sets_deployment_impact")

    def test_force_push_sets_deployment_impact(self):
        """A force-push to main (GIT-001) must set deployment_impact=True."""
        action = {"tool": "terminal", "command": "git push origin main --force"}
        eval_result = evaluate_action(action)
        report = analyze_blast_radius(action, eval_result=eval_result)
        assert report["deployment_impact"] is True, (
            "Expected deployment_impact=True for force-push action"
        )
        print("PASS  test_force_push_sets_deployment_impact")

    def test_notes_is_non_empty_list(self):
        """notes must be a non-empty list for any action."""
        action = {"tool": "terminal", "command": "DROP TABLE users;"}
        eval_result = evaluate_action(action)
        report = analyze_blast_radius(action, eval_result=eval_result)
        assert isinstance(report["notes"], list)
        assert len(report["notes"]) > 0
        print("PASS  test_notes_is_non_empty_list")

    def test_drop_table_blast_includes_db(self):
        """A DROP TABLE action must name DB components in blast radius."""
        action = {"tool": "terminal", "command": "DROP TABLE users;"}
        eval_result = evaluate_action(action)
        report = analyze_blast_radius(action, eval_result=eval_result)
        assert len(report["affected_db_components"]) > 0, (
            "Expected DB components in blast radius for DROP TABLE action"
        )
        print("PASS  test_drop_table_blast_includes_db")

    def test_works_without_eval_result(self):
        """analyze_blast_radius must work when eval_result is omitted."""
        action = {"tool": "terminal", "command": "deploy to production"}
        report = analyze_blast_radius(action)  # no eval_result
        # deployment_impact should still be set by the keyword scan
        assert report["deployment_impact"] is True
        print("PASS  test_works_without_eval_result")

    def test_works_with_repo_components(self):
        """Passing repo_components does not crash and may enrich the report."""
        from repo_analyzer import analyze_repo
        repo_info = analyze_repo()
        action = {
            "tool": "edit_file",
            "file_path": "services/reset.py",
            "command": "store reset token plaintext in database",
        }
        eval_result = evaluate_action(action)
        # Should not raise
        report = analyze_blast_radius(
            action,
            eval_result=eval_result,
            repo_components=repo_info["components"]
        )
        assert isinstance(report["affected_files"], list)
        print("PASS  test_works_with_repo_components")


# ===========================================================================
# Direct runner
# ===========================================================================

if __name__ == "__main__":
    test_classes = [TestRepoAnalyzer, TestEvidenceExtraction, TestBlastRadius]

    passed = 0
    failed = 0

    for cls in test_classes:
        instance = cls()
        methods = [m for m in dir(instance) if m.startswith("test_")]
        print(f"\n--- {cls.__name__} ---")
        for method_name in methods:
            method = getattr(instance, method_name)
            try:
                method()
                passed += 1
            except Exception as e:
                print(f"FAIL  {method_name}: {e}")
                failed += 1

    print(f"\n{passed + failed} tests | {passed} passed | {failed} failed")
    sys.exit(0 if failed == 0 else 1)
