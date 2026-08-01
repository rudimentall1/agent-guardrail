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

    def test_unknown_method_returns_error(self):
        response = self.server.handle({"jsonrpc": "2.0", "id": 5, "method": "nonexistent/method"})
        self.assertIn("error", response)


if __name__ == "__main__":
    unittest.main()
