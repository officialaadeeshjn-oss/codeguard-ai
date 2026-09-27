# CodeGuard AI

Policy gate for AI coding agents. Before a tool call runs, CodeGuard evaluates it against a small set of security policies, records the decision, and can block unsafe actions.

The live path today is:

**Understand → Predict → Govern → Prove → Execute → Verify → Audit**

The IBM Bob PreToolUse hook is what actually stops a tool. The rest of `engine/` builds evidence, blast radius, safer plans, test cases, approval records, rollback checks, and a Trust Receipt around that decision.

## What it does

Given a proposed action (command, file edit, deploy, and so on), CodeGuard returns one of:

| Decision | Meaning |
| --- | --- |
| `ALLOW` | No matching policy. The action may proceed. |
| `WARN` | Flagged but not blocked (reserved; no current policy emits this). |
| `APPROVAL_REQUIRED` | Human approval is required (production deploy). |
| `BLOCK` | The action must not run. Approval cannot override a block. |

The evaluator is deterministic pattern matching over the action JSON. It does not execute the command or call an LLM.

## Repository layout

```
.
├── dashboard.py              # Local web UI + HTTP API
├── engine/                   # Policy engine and supporting phases
│   ├── evaluator.py          # Policy decisions
│   ├── policies.json         # Policy catalog
│   ├── repo_analyzer.py      # Repo component snapshot
│   ├── evidence.py           # Structured evidence from an action
│   ├── blast_radius.py      # Likely-affected files, APIs, DB, tests
│   ├── safer_plan.py         # Safer alternative steps after a flag
│   ├── attack_tests.py       # Security test-case descriptions
│   ├── test_gate.py          # PASS / FAIL / NOT_RUN over actual results
│   ├── approval.py           # Human approval records
│   ├── rollback.py           # Rollback path verdict
│   ├── audit_event.py        # Immutable audit snapshot
│   ├── trust_receipt.py      # Assembled Trust Receipt
│   └── timeline.py           # Replay timeline of phases
├── hooks/                    # IBM Bob PreToolUse / PostToolUse gate
│   ├── codeguard_hook.py
│   └── codeguard_post_hook.py
├── data/
│   └── codeguard_audit.jsonl # Append-only audit log
├── api/                      # Placeholder (empty)
├── frontend/                 # Placeholder (empty)
└── demo-app/                 # Placeholder (empty)
```

`.bob/settings.json` wires the hooks into Bob. That directory is gitignored; copy or recreate the hook config locally if you need it.

`api/`, `frontend/`, and `demo-app/` exist as reserved directories. They currently have no files. The HTTP API and UI live in `dashboard.py`. The engine's repo analyzer and blast-radius heuristics still look for typical paths under `api/` and `frontend/` when those files exist.

## Policies

Defined in `engine/policies.json` and enforced in `engine/evaluator.py`:

| ID | Name | Decision |
| --- | --- | --- |
| SEC-001 | Hardcoded secrets | BLOCK |
| AUTH-001 | Authentication bypass | BLOCK |
| AUTH-002 | Plaintext password-reset tokens | BLOCK |
| DATA-001 | Destructive database action | BLOCK |
| GIT-001 | Force-push to protected `main` | BLOCK |
| DEPLOY-001 | Production deployment | APPROVAL_REQUIRED |

## Requirements

- Python 3 (stdlib only for the dashboard, engine, and hooks)
- `pytest` optional, for the test suite

No other packages are required to run the dashboard or the Bob hooks.

## Quick start

### Dashboard

From the repo root:

```bash
python dashboard.py
```

Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/).

The page shows recent audit events, policy trigger counts, and a live checker that posts to the same evaluator used by the hooks.

### HTTP API

Served by `dashboard.py` on port 8000.

**`GET /api/audit`**

Returns the last 100 lines of `data/codeguard_audit.jsonl` as a JSON array.

**`POST /api/check`**

Body:

```json
{ "command": "DROP TABLE users;" }
```

Response is the evaluator result (`decision` + `matched_policies`). The request is also appended to the audit log with tool `live_check`.

### Evaluate from the command line

```bash
python engine/evaluator.py
```

That runs a sample `DROP TABLE` action. From your own code:

```python
from evaluator import evaluate_action

result = evaluate_action({
    "tool": "terminal",
    "command": "git push --force origin main",
})
print(result["decision"])  # BLOCK
```

## IBM Bob integration

Bob runs `hooks/codeguard_hook.py` on every PreToolUse event (stdin JSON in, stdout permission JSON out).

- `ALLOW` / `WARN` / `APPROVAL_REQUIRED` → exit `0` (allow response)
- `BLOCK` → exit `2` (deny response; Bob stops the tool)

`hooks/codeguard_post_hook.py` logs that an allowed tool finished. It never blocks.

Manual hook test:

```bash
echo '{"session_id":"test","cwd":".","hook_event_name":"PreToolUse","tool_name":"execute_command","tool_input":{"command":"DROP TABLE users;"},"tool_use_id":"t1"}' | python hooks/codeguard_hook.py
```

On Windows, use `python` if `python3` is not on your PATH. Update `.bob/settings.json` to match.

## Tests

```bash
python -m pytest engine/test_evaluator.py engine/test_phase3.py engine/test_phase4.py engine/test_phase5.py engine/test_phase6.py engine/test_gate.py hooks/test_phase7.py -v
```

Each file can also be run directly, for example:

```bash
python engine/test_evaluator.py
python hooks/test_phase7.py
```

## Audit log

Path: `data/codeguard_audit.jsonl` (one JSON object per line).

Typical fields: `timestamp`, `tool`, `action`, `decision`, `policy_ids`, `reasons`. Bob events also include `session_id` and `hook_event`. PostToolUse entries set `completed: true`.

## Engine modules (beyond the live gate)

These are used for analysis, receipts, and tests. The Bob hook currently calls `evaluate_action` only.

| Module | Role |
| --- | --- |
| `repo_analyzer` | Maps known files/folders in a repo (auth, routes, models, tests). |
| `evidence` | Attaches file, API, and DB hints to an evaluation. |
| `blast_radius` | Heuristic “likely affected” files, APIs, DB, tests, deploy flag. |
| `safer_plan` | Policy-specific safer steps and verification notes. |
| `attack_tests` | Named security test cases to run before proceeding. |
| `test_gate` | Combines generated tests with actual pass/fail results. |
| `approval` | Pending / approved / rejected / blocked records. |
| `rollback` | `AVAILABLE` / `UNAVAILABLE` / `NOT_VERIFIED` from caller evidence. |
| `audit_event` | Combined status snapshot for logging and receipts. |
| `trust_receipt` | Honest assembled receipt (`NOT_AVAILABLE` / `NOT_RUN` when data is missing). |
| `timeline` | Ordered replay of the phases that actually ran. |

## License

Not specified in this repository.
