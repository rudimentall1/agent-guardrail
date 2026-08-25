"""An MCP server that is itself the enforcement boundary — not an
advisory checker the model has to remember to call.

``mcp_server.py``'s ``guardrail_check`` tool is honest about being
advisory (its own module docstring says so): it tells the model whether
an action would be ALLOWed, WARNed, or BLOCKed, but the model still has
a *separate* tool (or its own direct API access) to actually perform
that action - nothing stops it from skipping the check, or checking one
thing and doing another. ``decorator.py``'s ``enforce()`` closes that
gap for a Python codebase, by never giving the calling code a handle to
the unwrapped function at all. This module is the same guarantee, but
for an MCP integration: the model is never given a tool that performs
the real action directly. It's only ever given tools built by
``register_action()`` below - and those tools run the real action
themselves, internally, only after ``guardrail.enforcement.run_enforced``
says it's not blocked.

Usage - the operator registers real action executors when constructing
the server (these hold the real credentials/backends; the model that
talks to this server over MCP never sees them):

    from guardrail.mcp_enforced_server import EnforcedGuardrailMCPServer

    def do_transfer(request: ActionRequest) -> dict:
        wallet = get_wallet_for(request.agent_id)  # real credentials, held here
        tx_hash = wallet.transfer(to=request.arguments["to"], amount=request.arguments["amount"])
        return {"tx_hash": tx_hash}

    server = EnforcedGuardrailMCPServer(policy_path="policies/default.yaml")
    server.register_action(
        tool_name="wallet.transfer",
        description="Transfer funds from the agent's wallet.",
        input_schema={
            "type": "object",
            "properties": {"to": {"type": "string"}, "amount": {"type": "number"}},
            "required": ["to", "amount"],
        },
        executor=do_transfer,
    )
    server.serve_stdio()

The model calls the MCP tool named exactly ``wallet.transfer`` (with an
``agent_id`` argument added automatically to the schema) - it has no
other way to move funds through this server. A BLOCK decision means
``do_transfer`` never runs at all.

WARN handling: pass ``on_warn`` to ``register_action()`` (same
``Callable[[GuardrailDecision], bool]`` signature ``enforce()`` and
``run_enforced()`` use) to route a WARN to a human before proceeding -
e.g. ``guardrail.confirmation.web_ui.ConfirmationServer().request_confirmation``.
Without one, WARN proceeds - same documented default as everywhere else
in this project.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from guardrail.core.models import ActionRequest, GuardrailDecision
from guardrail.core.policy import Policy
from guardrail.engine import GuardrailEngine
from guardrail.enforcement import BlockedActionError, run_enforced
from guardrail.storage.aggregate_spend import AggregateSpendTracker
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "guardrail-enforced"
SERVER_VERSION = "1.0.0"


@dataclass
class RegisteredAction:
    tool_name: str
    description: str
    input_schema: Dict[str, Any]
    executor: Callable[[ActionRequest], Any]
    on_warn: Optional[Callable[[GuardrailDecision], bool]]


def _text_result(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, indent=2, default=str)}]}


class EnforcedGuardrailMCPServer:
    def __init__(self, policy_path: str = "policies/default.yaml", audit_db: str = "guardrail_audit.db"):
        from guardrail.__main__ import resolve_policy

        policy = resolve_policy(policy_path)
        self.engine = GuardrailEngine(
            policy=policy,
            audit_log=AuditLog(audit_db),
            rate_limiter=RateLimiter(audit_db.replace(".db", "_ratelimit.db")),
            aggregate_tracker=AggregateSpendTracker(audit_db.replace(".db", "_aggregate.db")),
        )
        self._actions: Dict[str, RegisteredAction] = {}

    def register_action(
        self,
        tool_name: str,
        description: str,
        input_schema: Dict[str, Any],
        executor: Callable[[ActionRequest], Any],
        on_warn: Optional[Callable[[GuardrailDecision], bool]] = None,
    ) -> None:
        """Exposes a real, gated action as an MCP tool named ``tool_name``.

        ``input_schema`` is a JSON Schema object for the arguments the
        model supplies (same shape as any MCP ``inputSchema``) - do not
        include ``agent_id`` in it, this adds that automatically so every
        registered action is identity-bound the same way.

        ``executor`` receives the built ``ActionRequest`` and performs the
        real side effect; this is the ONLY code path that can do so for
        this ``tool_name`` through this server - there's no way for the
        model to call it directly, only through the gated tool this
        creates.
        """
        if tool_name in self._actions:
            raise ValueError(f"An action is already registered for tool_name={tool_name!r}")
        full_schema = dict(input_schema)
        properties = dict(full_schema.get("properties") or {})
        properties["agent_id"] = {"type": "string", "description": "Identifier of the calling agent"}
        full_schema["properties"] = properties
        required = list(full_schema.get("required") or [])
        if "agent_id" not in required:
            required.append("agent_id")
        full_schema["required"] = required

        self._actions[tool_name] = RegisteredAction(
            tool_name=tool_name, description=description, input_schema=full_schema,
            executor=executor, on_warn=on_warn,
        )

    def _tool_list(self) -> list:
        return [
            {"name": a.tool_name, "description": a.description, "inputSchema": a.input_schema}
            for a in self._actions.values()
        ]

    def handle(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = message.get("method")
        msg_id = message.get("id")

        if method == "initialize":
            return self._response(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            })

        if method == "notifications/initialized":
            return None

        if method == "ping":
            return self._response(msg_id, {})

        if method == "tools/list":
            return self._response(msg_id, {"tools": self._tool_list()})

        if method == "tools/call":
            return self._handle_tool_call(msg_id, message.get("params", {}) or {})

        if msg_id is not None:
            return self._error(msg_id, -32601, f"Method not found: {method}")
        return None

    def _handle_tool_call(self, msg_id, params: Dict[str, Any]) -> Dict[str, Any]:
        name = params.get("name")
        arguments = dict(params.get("arguments") or {})

        action = self._actions.get(name)
        if action is None:
            return self._error(msg_id, -32602, f"Unknown tool: {name}")

        try:
            agent_id = arguments.pop("agent_id")
        except KeyError:
            return self._error(msg_id, -32602, "Missing required argument: 'agent_id'")

        request = ActionRequest(agent_id=agent_id, tool_name=action.tool_name, arguments=arguments)

        try:
            outcome = run_enforced(self.engine, request, executor=action.executor, on_warn=action.on_warn)
            return self._response(msg_id, _text_result({
                "decision": outcome.decision.to_dict(),
                "result": outcome.result,
            }))
        except BlockedActionError as e:
            # A blocked action is a normal, expected outcome the model
            # needs to see and adapt to - not a protocol-level error, so
            # this returns a regular tool result (with isError set) with
            # the decision's explanation, the same way a real backend
            # failure would surface. The real executor never ran.
            return self._response(msg_id, {
                "content": [{"type": "text", "text": json.dumps({
                    "decision": e.decision.to_dict(),
                    "result": None,
                }, indent=2, default=str)}],
                "isError": True,
            })
        except Exception as e:  # keep the server alive on unexpected executor errors
            return self._response(msg_id, {
                "content": [{"type": "text", "text": f"Tool execution error: {e}"}],
                "isError": True,
            })

    @staticmethod
    def _response(msg_id, result: Dict[str, Any]) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _error(msg_id, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    def serve_stdio(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            response = self.handle(message)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
