"""Example: wrapping real tool functions so an agent cannot bypass policy.

Run:

    python3 examples/example_agent_usage.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guardrail.core.policy import Policy
from guardrail.decorator import BlockedActionError, enforce
from guardrail.engine import GuardrailEngine
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter

policy = Policy.from_yaml_file(str(Path(__file__).resolve().parent.parent / "policies" / "default.yaml"))
engine = GuardrailEngine(
    policy=policy,
    audit_log=AuditLog(":memory:"),
    rate_limiter=RateLimiter(":memory:"),
)


def ask_human_to_confirm(decision) -> bool:
    """A real confirmation gate — replace with a Slack prompt, a CLI input(),
    a ticket, whatever fits your system. Returning False blocks the action."""
    print(f"  [confirmation required] {decision.explanation}")
    return True  # auto-approve for this demo; a real gate would ask a human


@enforce(engine, tool_name="wallet.transfer", on_warn=ask_human_to_confirm)
def transfer_funds(agent_id: str, to: str, amount: float):
    print(f"  -> executing transfer: {amount} to {to}")
    return {"status": "sent", "amount": amount, "to": to}


@enforce(engine, tool_name="execute_code", on_warn=ask_human_to_confirm)
def run_shell(agent_id: str, command: str):
    print(f"  -> executing shell command: {command}")
    return {"status": "ran", "command": command}


if __name__ == "__main__":
    print("1) Small, known-pattern transfer (should ALLOW/WARN and execute):")
    result = transfer_funds(agent_id="demo-agent", to="0xabc", amount=2)
    print("   result:", result)

    print("\n2) Oversized transfer from a brand-new agent (should BLOCK, never executes):")
    try:
        transfer_funds(agent_id="brand-new-agent", to="0xabc", amount=9999)
    except BlockedActionError as e:
        print("   blocked as expected:", e.decision.explanation)

    print("\n3) Destructive shell command (should BLOCK regardless of agent reputation):")
    try:
        run_shell(agent_id="demo-agent", command="rm -rf /")
    except BlockedActionError as e:
        print("   blocked as expected:", e.decision.explanation)
