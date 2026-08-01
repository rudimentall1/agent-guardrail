"""Command-line interface for quick manual checks and policy testing.

    python3 cli.py check --agent trading-agent-001 --tool wallet.transfer \
        --args '{"amount": 500, "to": "0xabc"}'

    python3 cli.py history --agent trading-agent-001
"""
from __future__ import annotations

import argparse
import json
import sys

from guardrail.core.models import ActionRequest
from guardrail.core.policy import Policy
from guardrail.engine import GuardrailEngine
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter


def build_engine(policy_path: str, audit_db: str) -> GuardrailEngine:
    policy = Policy.from_yaml_file(policy_path)
    return GuardrailEngine(
        policy=policy,
        audit_log=AuditLog(audit_db),
        rate_limiter=RateLimiter(audit_db.replace(".db", "_ratelimit.db")),
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="guardrail-cli")
    parser.add_argument("--policy", default="policies/default.yaml")
    parser.add_argument("--audit-db", default="guardrail_audit.db")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Evaluate a single action against the policy")
    check.add_argument("--agent", required=True)
    check.add_argument("--tool", required=True)
    check.add_argument("--args", default="{}", help="JSON-encoded arguments, e.g. '{\"amount\": 5}'")

    history = sub.add_parser("history", help="Show decision history for an agent")
    history.add_argument("--agent", required=True)
    history.add_argument("--limit", type=int, default=20)

    args = parser.parse_args()
    engine = build_engine(args.policy, args.audit_db)

    if args.command == "check":
        try:
            arguments = json.loads(args.args)
        except json.JSONDecodeError as e:
            print(f"Invalid --args JSON: {e}", file=sys.stderr)
            sys.exit(2)

        request = ActionRequest(agent_id=args.agent, tool_name=args.tool, arguments=arguments)
        decision = engine.evaluate(request)
        print(json.dumps(decision.to_dict(), indent=2))
        sys.exit(0 if decision.decision.value != "BLOCK" else 1)

    if args.command == "history":
        print(json.dumps(engine.history_for_agent(args.agent, args.limit), indent=2))


if __name__ == "__main__":
    main()
