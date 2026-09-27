"""
engine/blast_radius.py
----------------------
Lightweight, deterministic blast-radius analyzer for CodeGuard AI.

For a proposed action it reports:
- Affected files  (from file_path in the action + policy-driven heuristics)
- Affected API endpoints / components
- Affected database / schema components
- Affected test files
- Deployment impact flag

Design principles
-----------------
- Deterministic: same input always produces the same output.
- No execution, no import tracing — pure text/path heuristics.
- Uses the repo_analyzer snapshot when provided to resolve real paths.
- Honest about scope: labels are "likely affected" not "definitely affected".
- Prototype-optimised for the CodeGuard demo repository structure.

Usage:
    from engine.blast_radius import analyze_blast_radius

    action = {
        "tool": "edit_file",
        "file_path": "services/reset.py",
        "command": "store reset token plaintext in database",
    }
    report = analyze_blast_radius(action)
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Policy → component-group mapping
# Which groups of repo components are typically affected by each policy.
# ---------------------------------------------------------------------------

_POLICY_BLAST = {
    "SEC-001": {
        "api":        ["Config / environment handling", "Any route that reads this credential"],
        "db":         [],
        "tests":      ["Credential / config tests"],
        "deployment": False,
    },
    "AUTH-001": {
        "api":        ["All protected API endpoints", "Authentication middleware"],
        "db":         ["User session store", "Token table"],
        "tests":      ["Authentication tests", "Protected-route tests"],
        "deployment": False,
    },
    "AUTH-002": {
        "api":        ["Password-reset endpoint", "OTP / token endpoint"],
        "db":         ["User table (reset_token column)", "Token store"],
        "tests":      ["Password-reset service tests", "OTP tests"],
        "deployment": False,
    },
    "DATA-001": {
        "api":        ["Any route that queries the affected table"],
        "db":         ["Affected database table", "Related foreign-key tables"],
        "tests":      ["Database integration tests", "Affected model tests"],
        "deployment": False,
    },
    "GIT-001": {
        "api":        [],
        "db":         [],
        "tests":      ["CI pipeline tests"],
        "deployment": True,
    },
    "DEPLOY-001": {
        "api":        ["All production API endpoints"],
        "db":         ["Production database"],
        "tests":      ["Smoke tests", "Integration tests"],
        "deployment": True,
    },
}

# File-path keywords → affected component group
_PATH_TO_API = [
    (["routes/auth",  "api/auth",  "controllers/auth"], "Authentication route"),
    (["routes/user",  "api/user",  "controllers/user"], "User management route"),
    (["routes/reset", "api/reset", "services/reset"],   "Password-reset route"),
    (["routes/",      "api/",      "controllers/"],     "Generic API route"),
    (["middleware/auth", "auth/middleware"],             "Auth middleware"),
    (["middleware/"],                                    "Generic middleware"),
    (["deploy",       "dockerfile", "docker-compose",
      "workflow",     ".github",    "k8s"],              "Deployment pipeline"),
]

_PATH_TO_DB = [
    (["models/user",  "schemas/user",  "db/user"],      "User model"),
    (["models/",      "schemas/",      "db/"],           "Database model"),
    (["migration",    "migrate"],                        "Database migration"),
]

# File-path keywords → likely sibling/related files (relative patterns)
_SIBLING_HINTS = {
    "auth":        ["auth/middleware.*", "routes/auth.*", "models/user.*",
                    "services/reset.*",  "tests/test_auth.*"],
    "reset":       ["services/reset.*", "routes/auth.*", "models/user.*",
                    "tests/test_reset.*"],
    "middleware":  ["routes/",          "tests/test_middleware.*"],
    "model":       ["routes/",          "tests/test_model.*"],
    "deploy":      ["Dockerfile",       ".github/workflows/", "tests/smoke.*"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _match(path_str: str, patterns: list) -> str | None:
    """Return the first label whose keywords appear in the normalised path."""
    if not path_str:
        return None
    p = path_str.lower().replace("\\", "/")
    for keywords, label in patterns:
        if any(kw in p for kw in keywords):
            return label
    return None


def _sibling_hints_for(file_path: str) -> list:
    """Return likely related file patterns based on the changed file path."""
    if not file_path:
        return []
    fp = file_path.lower().replace("\\", "/")
    hints = []
    for keyword, patterns in _SIBLING_HINTS.items():
        if keyword in fp:
            hints.extend(patterns)
    return list(dict.fromkeys(hints))  # deduplicate, preserve order


def _resolve_real_files(patterns: list, repo_components: dict) -> list:
    """
    Given a list of glob-style hints and the repo_analyzer component dict,
    return any real files from the repo that match.
    """
    real = []
    all_files = []
    for key in ("test_files",):
        all_files.extend(repo_components.get(key, []))
    # Also include all known component paths
    for key, paths in repo_components.items():
        all_files.extend(paths)

    for pattern in patterns:
        stem = pattern.rstrip("*./").lower().replace("\\", "/")
        for f in all_files:
            if stem in f.lower().replace("\\", "/"):
                if f not in real:
                    real.append(f)
    return real


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_blast_radius(action: dict,
                         eval_result: dict = None,
                         repo_components: dict = None) -> dict:
    """
    Compute and return a blast-radius report for a proposed action.

    Parameters
    ----------
    action          : the raw action dict (same shape as evaluate_action input)
    eval_result     : optional dict returned by evaluate_action — used to pull
                      matched policy IDs for richer analysis
    repo_components : optional dict from analyze_repo()["components"] — used
                      to resolve real file paths in the repository

    Returns
    -------
    dict with keys:
        affected_files          – list of file paths / patterns likely affected
        affected_api_endpoints  – list of API component labels
        affected_db_components  – list of DB/schema component labels
        affected_tests          – list of test file paths / patterns
        deployment_impact       – bool
        notes                   – list of human-readable explanation strings
    """
    import json

    file_path       = action.get("file_path") or action.get("path") or ""
    matched_policies = []
    if eval_result:
        matched_policies = eval_result.get("matched_policies", [])

    action_text = json.dumps(action).lower()

    affected_files:   list = []
    affected_api:     list = []
    affected_db:      list = []
    affected_tests:   list = []
    deployment_impact: bool = False
    notes:            list = []

    # 1. Direct file from the action
    if file_path:
        affected_files.append(file_path)
        notes.append(f"Directly modified file: {file_path}")

    # 2. API component from file path
    api_from_path = _match(file_path, _PATH_TO_API)
    if api_from_path:
        affected_api.append(api_from_path)

    # 3. DB component from file path
    db_from_path = _match(file_path, _PATH_TO_DB)
    if db_from_path:
        affected_db.append(db_from_path)

    # 4. Policy-driven blast radius
    for m in matched_policies:
        pid = m["policy_id"]
        blast = _POLICY_BLAST.get(pid, {})

        for item in blast.get("api", []):
            if item not in affected_api:
                affected_api.append(item)

        for item in blast.get("db", []):
            if item not in affected_db:
                affected_db.append(item)

        for item in blast.get("tests", []):
            if item not in affected_tests:
                affected_tests.append(item)

        if blast.get("deployment", False):
            deployment_impact = True

        notes.append(
            f"Policy {pid} ({m['decision']}): blast radius includes "
            f"{len(blast.get('api', []))} API component(s), "
            f"{len(blast.get('db', []))} DB component(s), "
            f"{len(blast.get('tests', []))} test group(s)."
        )

    # 5. Sibling / related file hints from the changed file path
    sibling_patterns = _sibling_hints_for(file_path)
    if sibling_patterns:
        notes.append(f"Likely related files/patterns: {', '.join(sibling_patterns)}")

    # 6. Resolve real file paths from the repo snapshot (if provided)
    if repo_components and sibling_patterns:
        real = _resolve_real_files(sibling_patterns, repo_components)
        for f in real:
            if f not in affected_files:
                affected_files.append(f)
                notes.append(f"Real repo file also likely affected: {f}")

    # 7. Action-text keyword hints for API / DB when no file path was given
    if not file_path:
        if any(kw in action_text for kw in ["auth", "login", "token", "session"]):
            if "Authentication component" not in affected_api:
                affected_api.append("Authentication component")
        if any(kw in action_text for kw in ["reset", "password", "otp"]):
            if "Password-reset component" not in affected_api:
                affected_api.append("Password-reset component")
            if "User / reset-token table" not in affected_db:
                affected_db.append("User / reset-token table")
        if any(kw in action_text for kw in ["drop table", "drop database",
                                             "truncate", "delete all"]):
            if "Affected database table" not in affected_db:
                affected_db.append("Affected database table")
        if any(kw in action_text for kw in ["deploy", "production"]):
            deployment_impact = True

    # 8. Deployment impact from file path
    if _match(file_path, [
        (["dockerfile", "docker-compose", "workflow", ".github",
          "deploy", "k8s", "kubernetes"], "deployment")
    ]):
        deployment_impact = True

    if deployment_impact:
        notes.append("Deployment pipeline is in blast radius.")

    if not affected_api and not affected_db and not matched_policies:
        notes.append("No significant blast radius detected.")

    return {
        "affected_files":         affected_files,
        "affected_api_endpoints": affected_api,
        "affected_db_components": affected_db,
        "affected_tests":         affected_tests,
        "deployment_impact":      deployment_impact,
        "notes":                  notes,
    }


if __name__ == "__main__":
    import json
    from pathlib import Path
    import sys
    sys.path.insert(0, str(Path(__file__).parent))

    from evaluator import evaluate_action

    action = {
        "tool": "edit_file",
        "file_path": "services/reset.py",
        "command": "store reset token plaintext in database",
    }
    result = evaluate_action(action)
    report = analyze_blast_radius(action, eval_result=result)
    print(json.dumps(report, indent=2))
