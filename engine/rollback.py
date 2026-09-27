"""
engine/rollback.py
------------------
Rollback-verification component for CodeGuard AI.

Determines whether a proposed action has a known rollback path, based
solely on the evidence supplied by the caller.

Design principles
-----------------
- Deterministic: same evidence → same verdict.
- Honest: NEVER claims rollback is available unless evidence explicitly
  says so.  Absence of evidence is NOT_VERIFIED, not AVAILABLE.
- No side effects: does not write files, execute commands, or make
  network calls.

Verdict values
--------------
  AVAILABLE     – at least one piece of explicit positive rollback evidence
                  was supplied and none of the hard-blockers are present.
  UNAVAILABLE   – caller explicitly stated rollback is not possible, OR a
                  hard-blocker pattern was detected (e.g. irreversible
                  destructive operation with no backup).
  NOT_VERIFIED  – no rollback evidence was supplied; we cannot determine
                  whether rollback is possible.

Evidence keys (all optional, all boolean unless noted)
-------------------------------------------------------
  backup_available         (bool) – a verified backup exists
  reversible_file_change   (bool) – the file change can be undone (e.g. git revert)
  migration_rollback       (bool) – the DB migration has a down() / rollback script
  deployment_rollback      (bool) – the deployment can be rolled back (prior image tag etc.)
  rollback_explicitly_unavailable (bool) – caller asserts rollback is impossible
  notes                    (str)  – optional human-readable context; stored as-is

Usage:
    from engine.rollback import verify_rollback

    # File change with git
    result = verify_rollback({"reversible_file_change": True})
    # result["verdict"] == "AVAILABLE"

    # Destructive SQL, no backup
    result = verify_rollback({"rollback_explicitly_unavailable": True})
    # result["verdict"] == "UNAVAILABLE"

    # Nothing provided
    result = verify_rollback({})
    # result["verdict"] == "NOT_VERIFIED"
"""

# Keys that signal a positive rollback path
_POSITIVE_KEYS = (
    "backup_available",
    "reversible_file_change",
    "migration_rollback",
    "deployment_rollback",
)

# Key that hard-blocks rollback
_BLOCKER_KEY = "rollback_explicitly_unavailable"


def verify_rollback(evidence: dict = None) -> dict:
    """
    Determine whether the proposed action has a rollback path.

    Parameters
    ----------
    evidence : dict with any of the keys described in the module docstring.
               Pass an empty dict or None to indicate no evidence.

    Returns
    -------
    dict with keys:
        verdict          – "AVAILABLE" | "UNAVAILABLE" | "NOT_VERIFIED"
        positive_signals – list of evidence keys that confirmed rollback
        blocker          – True if the hard-blocker key was set, else False
        notes            – human-readable explanation
        raw_evidence     – the evidence dict exactly as supplied
    """
    if evidence is None:
        evidence = {}

    positive_signals = [k for k in _POSITIVE_KEYS if evidence.get(k) is True]
    blocker          = bool(evidence.get(_BLOCKER_KEY))

    # Determine verdict
    if blocker:
        verdict = "UNAVAILABLE"
        notes   = (
            "Rollback has been explicitly marked as unavailable. "
            "Do not proceed without a mitigation plan."
        )
    elif positive_signals:
        verdict = "AVAILABLE"
        notes   = (
            f"Rollback path confirmed via: {', '.join(positive_signals)}."
        )
    else:
        verdict = "NOT_VERIFIED"
        notes   = (
            "No rollback evidence was supplied. "
            "Rollback availability could not be determined. "
            "Provide evidence (backup_available, reversible_file_change, "
            "migration_rollback, or deployment_rollback) to resolve this."
        )

    # Append caller's own notes if present
    caller_notes = evidence.get("notes", "")
    if caller_notes:
        notes = notes + f" Additional context: {caller_notes}"

    return {
        "verdict":          verdict,
        "positive_signals": positive_signals,
        "blocker":          blocker,
        "notes":            notes,
        "raw_evidence":     dict(evidence),
    }


if __name__ == "__main__":
    import json

    scenarios = [
        ({},                                             "no evidence"),
        ({"backup_available": True},                     "backup available"),
        ({"reversible_file_change": True},               "reversible file change"),
        ({"migration_rollback": True},                   "migration rollback"),
        ({"deployment_rollback": True},                  "deployment rollback"),
        ({"rollback_explicitly_unavailable": True},      "explicitly unavailable"),
        ({"backup_available": True,
          "rollback_explicitly_unavailable": True},      "backup + explicit blocker"),
    ]

    for ev, label in scenarios:
        result = verify_rollback(ev)
        print(f"\n--- {label} ---")
        print(json.dumps(result, indent=2))
