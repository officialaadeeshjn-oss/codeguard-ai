"""
engine/evidence.py
------------------
Evidence extraction for CodeGuard AI.

Takes a proposed action dict and the evaluator's output dict (already
computed by evaluate_action) and enriches them with structured evidence:
- what tool/action was proposed
- which file is affected, if detectable
- which code/config location is relevant
- which policy matched and why
- which API component is relevant, if detectable
- which database/schema component is relevant, if detectable

This module does NOT re-run policy evaluation.  It wraps the evaluator
output that was already computed.

Usage:
    from engine.evaluator import evaluate_action
    from engine.evidence import extract_evidence

    action = {"tool": "edit_file", "file_path": "auth/middleware.py",
              "code": "// bypass authentication"}
    eval_result = evaluate_action(action)
    evidence = extract_evidence(action, eval_result)
"""

# ---------------------------------------------------------------------------
# Keyword maps: policy ID → components it is related to
# ---------------------------------------------------------------------------

# Which API keywords signal relevance for each policy
_POLICY_API_HINTS = {
    "AUTH-001": ["auth", "login", "logout", "session", "jwt", "oauth", "middleware"],
    "AUTH-002": ["auth", "reset", "password", "otp", "token"],
    "SEC-001":  ["auth", "api", "config", "env", "secret", "key"],
    "DATA-001": ["database", "db", "sql", "migration", "schema"],
    "GIT-001":  [],
    "DEPLOY-001": ["deploy", "ci", "cd", "pipeline", "workflow"],
}

# Which DB keywords signal relevance for each policy
_POLICY_DB_HINTS = {
    "AUTH-001": ["user", "session", "token"],
    "AUTH-002": ["user", "reset_token", "otp", "password_reset"],
    "SEC-001":  [],
    "DATA-001": ["user", "database", "schema", "table"],
    "GIT-001":  [],
    "DEPLOY-001": [],
}

# Generic file-path patterns → API component label
_API_COMPONENT_PATTERNS = [
    (["routes/auth",  "api/auth",   "controllers/auth"], "Authentication route"),
    (["routes/user",  "api/user",   "controllers/user"], "User route"),
    (["routes/reset", "api/reset",  "services/reset"],   "Password-reset route"),
    (["routes/",      "api/",       "controllers/"],     "API route"),
    (["middleware/auth", "auth/middleware"],              "Auth middleware"),
    (["middleware/"],                                     "Middleware"),
    (["deploy", "k8s", "kubernetes", "dockerfile",
      "docker-compose", "workflow", ".github"],           "Deployment config"),
]

# Generic file-path patterns → DB component label
_DB_COMPONENT_PATTERNS = [
    (["models/user",  "schemas/user",  "db/user"],       "User model"),
    (["models/",      "schemas/",      "db/"],            "Database model"),
    (["migration",    "migrate"],                         "Database migration"),
]


def _match_component(file_path: str, patterns: list) -> str | None:
    """Return the first label whose path keywords appear in file_path."""
    if not file_path:
        return None
    fp = file_path.lower().replace("\\", "/")
    for keywords, label in patterns:
        if any(kw in fp for kw in keywords):
            return label
    return None


def _hint_from_policy(policy_id: str, hint_map: dict, action_text: str) -> str | None:
    """
    Return a component hint derived from the action text when no file path is
    available.  Uses the keyword lists associated with the matched policy.
    """
    keywords = hint_map.get(policy_id, [])
    for kw in keywords:
        if kw in action_text:
            return kw.capitalize() + " component"
    return None


def extract_evidence(action: dict, eval_result: dict) -> dict:
    """
    Build and return a structured evidence dict for a proposed action.

    Parameters
    ----------
    action      : the raw action dict passed to evaluate_action
    eval_result : the dict returned by evaluate_action

    Returns
    -------
    dict with keys:
        tool            – value of action["tool"] or None
        affected_file   – value of action["file_path"] or None
        code_location   – short label describing the file role, if detectable
        matched_policies – list of {policy_id, decision, reason} from evaluator
        final_decision  – the top-level decision string
        api_component   – nearest API component, if detectable
        db_component    – nearest DB/schema component, if detectable
        notes           – list of human-readable notes assembled from evidence
    """
    import json

    tool          = action.get("tool")
    file_path     = action.get("file_path") or action.get("path") or ""
    matched       = eval_result.get("matched_policies", [])
    final_decision = eval_result.get("decision", "ALLOW")

    # Serialise the full action for keyword scanning
    action_text = json.dumps(action).lower()

    # --- code location -------------------------------------------------------
    code_location = _match_component(file_path, _API_COMPONENT_PATTERNS) or \
                    _match_component(file_path, _DB_COMPONENT_PATTERNS)

    # --- api component -------------------------------------------------------
    api_component = _match_component(file_path, _API_COMPONENT_PATTERNS)
    if not api_component and matched:
        # Fall back to policy-specific keyword scan of the whole action text
        for m in matched:
            hint = _hint_from_policy(m["policy_id"], _POLICY_API_HINTS, action_text)
            if hint:
                api_component = hint
                break

    # --- db component --------------------------------------------------------
    db_component = _match_component(file_path, _DB_COMPONENT_PATTERNS)
    if not db_component and matched:
        for m in matched:
            hint = _hint_from_policy(m["policy_id"], _POLICY_DB_HINTS, action_text)
            if hint:
                db_component = hint
                break

    # --- notes ---------------------------------------------------------------
    notes = []
    if tool:
        notes.append(f"Tool used: {tool}")
    if file_path:
        notes.append(f"Affected file: {file_path}")
    for m in matched:
        notes.append(
            f"Policy {m['policy_id']} triggered ({m['decision']}): {m['reason']}"
        )
    if api_component:
        notes.append(f"Related API component: {api_component}")
    if db_component:
        notes.append(f"Related DB component: {db_component}")
    if not matched:
        notes.append("No policies matched — action is permitted.")

    return {
        "tool":             tool,
        "affected_file":    file_path or None,
        "code_location":    code_location,
        "matched_policies": matched,
        "final_decision":   final_decision,
        "api_component":    api_component,
        "db_component":     db_component,
        "notes":            notes,
    }


if __name__ == "__main__":
    import json
    from pathlib import Path
    import sys
    sys.path.insert(0, str(Path(__file__).parent))

    from evaluator import evaluate_action

    action = {
        "tool": "edit_file",
        "file_path": "auth/middleware.py",
        "code": "// bypass authentication for internal routes",
    }
    result = evaluate_action(action)
    evidence = extract_evidence(action, result)
    print(json.dumps(evidence, indent=2))
