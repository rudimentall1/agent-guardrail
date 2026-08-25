"""The single implementation of "actually enforce a decision" — check,
maybe route to a human on WARN, run the real action only if not blocked,
report the real outcome back.

``decorator.py``'s ``enforce()`` and ``mcp_enforced_server.py``'s
enforced tool calls are two different *callers* of this — a synchronous
Python function call in one case, an MCP ``tools/call`` message in the
other — but the actual enforcement guarantee (an action that would be
blocked never runs; a WARN a human rejects never runs; the audit trail
and aggregate spend tracking reflect what really happened, not just what
was requested) needs to be exactly the same logic in both places. Two
independent implementations of "when does the real action actually run"
is exactly the kind of thing that quietly drifts apart over time - one
gets a fix the other doesn't - and this is the one place in the whole
project where that would silently reopen the gap this project exists to
close. So there is exactly one implementation, here, and both callers
use it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from guardrail.core.models import ActionRequest, Decision, GuardrailDecision


class BlockedActionError(Exception):
    def __init__(self, decision: GuardrailDecision):
        self.decision = decision
        super().__init__(f"Action blocked by policy: {decision.explanation}")


@dataclass
class EnforcementResult:
    decision: GuardrailDecision
    result: Any


def run_enforced(
    engine,
    request: ActionRequest,
    executor: Callable[[ActionRequest], Any],
    on_warn: Optional[Callable[[GuardrailDecision], bool]] = None,
) -> EnforcementResult:
    """Evaluate ``request``, then run ``executor(request)`` only if the
    decision doesn't block it — and only ``executor``, nothing else, is
    what actually performs the real action, regardless of caller.

    Raises ``BlockedActionError`` (never calls ``executor``) when the
    decision is BLOCK, or when it's WARN and ``on_warn`` returns False.
    Without an ``on_warn`` callback, WARN allows execution to proceed -
    same documented trade-off as ``decorator.enforce()`` always had; set
    one for any tool where a human should be in the loop first (see
    ``confirmation/cli_ui.py`` and ``confirmation/web_ui.py``).

    Always reports the real outcome back to ``engine.record_outcome()`` -
    "success" if ``executor`` returned without raising, "error" if it
    raised (the exception still propagates after that). This is what
    keeps the audit trail, aggregate spend tracking (see
    ``storage/aggregate_spend.py``), and "known agent" status (see
    ``engine._is_known_agent``) honest: none of them count a BLOCKed or
    genuinely-failed action as if it had really happened.
    """
    decision = engine.evaluate(request)

    if decision.decision == Decision.BLOCK:
        raise BlockedActionError(decision)

    if decision.decision == Decision.WARN and on_warn is not None:
        if not on_warn(decision):
            raise BlockedActionError(decision)

    try:
        result = executor(request)
    except Exception:
        engine.record_outcome(decision.request_id, "error")
        raise
    engine.record_outcome(decision.request_id, "success")
    return EnforcementResult(decision=decision, result=result)
