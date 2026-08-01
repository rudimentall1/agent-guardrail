"""Terminal-based confirmation — the zero-setup alternative to the web UI.

    from guardrail.confirmation.cli_ui import cli_confirm

    @enforce(engine, tool_name="wallet.transfer", on_warn=cli_confirm)
    def transfer(...): ...

Blocks on a plain `input()` prompt in whatever terminal the process is
attached to. No server, no browser — good for scripts and local testing;
use `guardrail.confirmation.web_ui.ConfirmationServer` instead for
anything running unattended or where the operator isn't at that terminal.
"""
from __future__ import annotations

from guardrail.core.models import GuardrailDecision


def cli_confirm(decision: GuardrailDecision) -> bool:
    print(f"\n[guardrail] '{decision.tool_name}' from agent '{decision.agent_id}' needs confirmation:")
    for line in decision.explanation:
        print(f"  - {line}")
    answer = input("Approve? [y/N] ").strip().lower()
    return answer in ("y", "yes")
