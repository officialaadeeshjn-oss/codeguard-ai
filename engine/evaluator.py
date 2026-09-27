import json
import re
from pathlib import Path

POLICY_FILE = Path(__file__).parent / "policies.json"


def load_policies():
    with open(POLICY_FILE, "r", encoding="utf-8") as f:
        return json.load(f)["policies"]


def evaluate_action(action):
    text = json.dumps(action).lower()
    results = []

    for policy in load_policies():
        policy_id = policy["id"]
        decision = None
        reason = None

        if policy_id == "SEC-001":
            if re.search(r'(api[_-]?key|password|secret|token)\s*[:=]\s*(?:\\"|["\'])[^"\'\\]+(?:\\"|["\'])', text):
                decision = "BLOCK"
                reason = "Hardcoded secret or credential detected."

        elif policy_id == "AUTH-001":
            if any(x in text for x in [
                "disable auth",
                "bypass authentication",
                "skip authentication",
                "remove auth middleware"
            ]):
                decision = "BLOCK"
                reason = "Authentication bypass detected."

        elif policy_id == "AUTH-002":
            if "reset token" in text and any(x in text for x in [
                "plaintext",
                "plain text",
                "store token directly"
            ]):
                decision = "BLOCK"
                reason = "Password-reset token may be stored in plaintext."

        elif policy_id == "DATA-001":
            if any(x in text for x in [
                "drop table",
                "drop database",
                "delete all users",
                "truncate users"
            ]):
                decision = "BLOCK"
                reason = "Destructive database operation detected."

        elif policy_id == "GIT-001":
            if "git push" in text and "--force" in text and "main" in text:
                decision = "BLOCK"
                reason = "Force-push to protected main branch detected."

        elif policy_id == "DEPLOY-001":
            if any(x in text for x in [
                "production deploy",
                "deploy to production",
                "production deployment"
            ]):
                decision = "APPROVAL_REQUIRED"
                reason = "Production deployment requires human approval."

        if decision:
            results.append({
                "policy_id": policy_id,
                "decision": decision,
                "reason": reason
            })

    if any(r["decision"] == "BLOCK" for r in results):
        final_decision = "BLOCK"
    elif any(r["decision"] == "APPROVAL_REQUIRED" for r in results):
        final_decision = "APPROVAL_REQUIRED"
    elif any(r["decision"] == "WARN" for r in results):
        final_decision = "WARN"
    else:
        final_decision = "ALLOW"

    return {
        "decision": final_decision,
        "matched_policies": results
    }


if __name__ == "__main__":
    test_action = {
        "tool": "terminal",
        "command": "DROP TABLE users;"
    }

    print(json.dumps(evaluate_action(test_action), indent=2))