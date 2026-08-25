"""The actually-enforceable integration point.

An MCP tool (see mcp_server.py) is *advisory*: it works today with zero
extra infrastructure, but nothing stops the calling model from simply not
invoking it before acting. ``enforce`` closes that gap by wrapping the
real Python function that performs a tool's side effect — the check runs
in your code, before the wrapped function executes. A model can't argue
its way around this, because it never gets a chance to call the
underlying function directly; only the wrapped version is exposed to it.

    engine = GuardrailEngine(policy=Policy.from_yaml_file("policies/default.yaml"))

    @enforce(engine, tool_name="send_email")
    def send_email(agent_id: str, to: str, subject: str, body: str):
        ...  # real side effect — only runs if the decision is ALLOW or WARN

The actual enforcement logic (evaluate, maybe route WARN to a human,
run the real action only if not blocked, report the real outcome back)
lives in ``guardrail.enforcement.run_enforced`` - this decorator is a
thin adapter from "a Python function call" to that shared logic. See
``guardrail/mcp_enforced_server.py`` for the same guarantee exposed over
MCP instead of a Python decorator - both use the identical underlying
implementation, not two independently-maintained copies of it.
"""
from __future__ import annotations

import functools
from typing import Callable, Optional

from guardrail.core.models import ActionRequest, GuardrailDecision
from guardrail.enforcement import BlockedActionError, run_enforced

__all__ = ["enforce", "BlockedActionError"]


def enforce(engine, tool_name: str, agent_id_arg: str = "agent_id",
            on_warn: Optional[Callable[[GuardrailDecision], bool]] = None):
    """Decorator factory bound to a GuardrailEngine instance.

    ``agent_id_arg`` names the keyword argument the wrapped function
    receives that identifies the calling agent — pass agent_id as a
    keyword when calling the wrapped function.

    ``on_warn``, if provided, is called with the decision whenever the
    result is WARN (e.g. to route to a human-confirmation step). It should
    return True to proceed or False to block. Without an ``on_warn``
    callback, WARN allows execution to proceed — set one explicitly for
    any tool where a human should be in the loop before it runs.
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            agent_id = kwargs.get(agent_id_arg)
            if agent_id is None:
                raise TypeError(
                    f"enforce() could not find '{agent_id_arg}' among the keyword arguments "
                    f"to {func.__name__}(); call it with {agent_id_arg}=... ."
                )

            request = ActionRequest(agent_id=agent_id, tool_name=tool_name, arguments=dict(kwargs))
            outcome = run_enforced(engine, request, executor=lambda _req: func(*args, **kwargs), on_warn=on_warn)
            return outcome.result

        return wrapper
    return decorator
