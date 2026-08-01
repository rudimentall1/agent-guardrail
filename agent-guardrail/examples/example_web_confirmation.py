"""Example: routing WARN decisions to the real local web confirmation UI.

Run:

    python3 examples/example_web_confirmation.py

Then open http://localhost:8787 within 60 seconds (the script's timeout
for this demo) and click Approve or Reject. The script's call to
`transfer_funds` blocks until you respond, exactly like it would with a
real human operator.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guardrail.confirmation.web_ui import ConfirmationServer
from guardrail.core.policy import Policy
from guardrail.decorator import BlockedActionError, enforce
from guardrail.engine import GuardrailEngine
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter

policy = Policy.from_yaml_file(str(Path(__file__).resolve().parent.parent / "policies" / "default.yaml"))
engine = GuardrailEngine(policy=policy, audit_log=AuditLog(":memory:"), rate_limiter=RateLimiter(":memory:"))

confirmation = ConfirmationServer(port=8787, timeout_seconds=60)


@enforce(engine, tool_name="wallet.transfer", on_warn=confirmation.request_confirmation)
def transfer_funds(agent_id: str, to: str, amount: float):
    print(f"  -> executing transfer: {amount} to {to}")
    return {"status": "sent", "amount": amount, "to": to}


if __name__ == "__main__":
    confirmation.start(open_browser=True)
    print("Confirmation UI running at http://localhost:8787")
    print("Waiting up to 60s for you to Approve or Reject the transfer below...\n")

    try:
        result = transfer_funds(agent_id="demo-agent", to="0xabc", amount=2)
        print("\napproved — result:", result)
    except BlockedActionError as e:
        print("\nrejected or timed out:", e.decision.explanation)
    finally:
        confirmation.stop()
