"""Minimal MCP stdio server for Guardrail.

Implements exactly what's needed of the MCP spec (initialize,
notifications/initialized, ping, tools/list, tools/call) over
newline-delimited JSON-RPC 2.0 on stdio — see
https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
for the framing this follows. Deliberately hand-rolled instead of
depending on the official `mcp` SDK package, so this project's only real
dependency is PyYAML (for policy loading).

Add to Claude Desktop / Claude Code's MCP config:

    {
      "mcpServers": {
        "guardrail": {
          "command": "python3",
          "args": ["/absolute/path/to/mcp_server.py"],
          "env": {
            "GUARDRAIL_POLICY": "/absolute/path/to/policies/default.yaml"
          }
        }
      }
    }

IMPORTANT: this exposes Guardrail as an ADVISORY tool. Like any MCP tool,
nothing stops a model from simply not calling it before acting — it only
helps if the calling agent's instructions say to always check first. For
enforcement a model literally cannot bypass, wrap your real tool-execution
functions with guardrail.decorator.enforce instead (see README.md); this
server is the convenient on-ramp, the decorator is the actual guarantee.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional

from guardrail.core.models import ActionRequest
from guardrail.core.policy import Policy
from guardrail.engine import GuardrailEngine
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "guardrail"
SERVER_VERSION = "1.0.0"

TOOLS = [
    {
        "name": "guardrail_check",
        "description": (
            "Evaluate a proposed tool call against the Guardrail policy BEFORE executing it. "
            "Returns ALLOW, WARN, or BLOCK with a concrete explanation. Always call this before "
            "performing any action that spends money, deletes data, sends messages externally, "
            "or runs code."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "Identifier of the calling agent"},
                "tool_name": {"type": "string", "description": "Name of the tool/action being proposed"},
                "arguments": {"type": "object", "description": "Arguments the tool would be called with"},
            },
            "required": ["agent_id", "tool_name"],
        },
    },
    {
        "name": "guardrail_record_outcome",
        "description": "Record the real-world outcome (success/error) of a previously-checked action, for the audit trail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "outcome": {"type": "string", "enum": ["success", "error"]},
            },
            "required": ["request_id", "outcome"],
        },
    },
    {
        "name": "guardrail_agent_history",
        "description": "Return recent decision history for a given agent — a real, persisted audit trail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
            "required": ["agent_id"],
        },
    },
]


def _text_result(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}]}


class GuardrailMCPServer:
    def __init__(self, policy_path: str = "policies/default.yaml", audit_db: str = "guardrail_audit.db"):
        from guardrail.__main__ import resolve_policy

        policy = resolve_policy(policy_path)
        self.engine = GuardrailEngine(
            policy=policy,
            audit_log=AuditLog(audit_db),
            rate_limiter=RateLimiter(audit_db.replace(".db", "_ratelimit.db")),
        )

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
            return None  # notification: no response expected

        if method == "ping":
            return self._response(msg_id, {})

        if method == "tools/list":
            return self._response(msg_id, {"tools": TOOLS})

        if method == "tools/call":
            return self._handle_tool_call(msg_id, message.get("params", {}) or {})

        if msg_id is not None:
            return self._error(msg_id, -32601, f"Method not found: {method}")
        return None

    def _handle_tool_call(self, msg_id, params: Dict[str, Any]) -> Dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments") or {}

        try:
            if name == "guardrail_check":
                request = ActionRequest(
                    agent_id=arguments["agent_id"],
                    tool_name=arguments["tool_name"],
                    arguments=arguments.get("arguments") or {},
                )
                decision = self.engine.evaluate(request)
                return self._response(msg_id, _text_result(decision.to_dict()))

            if name == "guardrail_record_outcome":
                ok = self.engine.record_outcome(arguments["request_id"], arguments["outcome"])
                return self._response(msg_id, _text_result({"recorded": ok}))

            if name == "guardrail_agent_history":
                history = self.engine.history_for_agent(arguments["agent_id"], arguments.get("limit", 50))
                return self._response(msg_id, _text_result({"history": history}))

            return self._error(msg_id, -32602, f"Unknown tool: {name}")

        except KeyError as e:
            return self._error(msg_id, -32602, f"Missing required argument: {e}")
        except Exception as e:  # keep the server alive on unexpected tool errors
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


def main() -> None:
    policy_path = os.environ.get("GUARDRAIL_POLICY", "policies/default.yaml")
    audit_db = os.environ.get("GUARDRAIL_AUDIT_DB", "guardrail_audit.db")
    server = GuardrailMCPServer(policy_path=policy_path, audit_db=audit_db)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue  # per spec, the server MUST NOT write non-MCP content to stdout; just skip

        response = server.handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
