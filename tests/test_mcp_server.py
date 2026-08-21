import json
import os
import tempfile
import unittest

from guardrail.mcp_server import GuardrailMCPServer


class TestMCPServer(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.policy_path = os.path.join(os.path.dirname(__file__), "..", "policies", "default.yaml")
        self.audit_db = os.path.join(self.tmpdir, "audit.db")
        self.server = GuardrailMCPServer(policy_path=self.policy_path, audit_db=self.audit_db)

    def test_initialize_returns_protocol_info(self):
        response = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(response["id"], 1)
        self.assertIn("protocolVersion", response["result"])
        self.assertIn("serverInfo", response["result"])

    def test_initialized_notification_returns_nothing(self):
        response = self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertIsNone(response)

    def test_tools_list_returns_all_tools(self):
        response = self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in response["result"]["tools"]}
        self.assertEqual(names, {"guardrail_check", "guardrail_record_outcome", "guardrail_agent_history"})

    def test_tools_call_guardrail_check_blocks_destructive_command(self):
        response = self.server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "guardrail_check",
                "arguments": {
                    "agent_id": "test-agent",
                    "tool_name": "execute_code",
                    "arguments": {"command": "rm -rf /"},
                },
            },
        })
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["decision"], "BLOCK")

    def test_tools_call_unknown_tool_returns_error(self):
        response = self.server.handle({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "not_a_real_tool", "arguments": {}},
        })
        self.assertIn("error", response)

    def test_nan_in_raw_stdin_message_does_not_bypass_numeric_cap(self):
        """End-to-end regression test for Finding 2: main()'s stdin loop
        parses each line with `json.loads(line)` - the exact call used
        here - which accepts a bare NaN literal by default (a non-
        standard but enabled-by-default extension of Python's json
        module). This reproduces the real exploit path: raw JSON text
        with a NaN literal, parsed the same way the actual server does,
        flowing through the full tools/call pipeline against a tool that
        has a numeric cap in the real default policy (wallet.transfer)."""
        raw_line = (
            '{"jsonrpc": "2.0", "id": 6, "method": "tools/call", '
            '"params": {"name": "guardrail_check", "arguments": '
            '{"agent_id": "test-agent", "tool_name": "wallet.transfer", '
            '"arguments": {"amount": NaN}}}}'
        )
        message = json.loads(raw_line)  # same call main()'s stdin loop makes
        response = self.server.handle(message)
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertNotEqual(payload["decision"], "ALLOW",
                             msg=f"NaN amount was not caught - got: {payload}")
        rule_names = {m["rule"] for m in payload["matched_rules"]}
        self.assertIn("numeric_cap_invalid", rule_names)

    def test_unknown_method_returns_error(self):
        response = self.server.handle({"jsonrpc": "2.0", "id": 5, "method": "nonexistent/method"})
        self.assertIn("error", response)


if __name__ == "__main__":
    unittest.main()
