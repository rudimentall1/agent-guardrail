import unittest

from guardrail.core.policy import Policy
from guardrail.engine import GuardrailEngine
from guardrail.mcp_enforced_server import EnforcedGuardrailMCPServer
from guardrail.storage.aggregate_spend import AggregateSpendTracker
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter

TEST_POLICY = Policy.from_dict({
    "confirmation_required_tools": ["risky_action"],
    "numeric_caps": {
        "wallet.transfer": {"field": "amount", "max_unknown_agent": 5, "max_known_agent": 1000},
    },
})


def new_server() -> EnforcedGuardrailMCPServer:
    server = EnforcedGuardrailMCPServer.__new__(EnforcedGuardrailMCPServer)
    server.engine = GuardrailEngine(
        policy=TEST_POLICY, audit_log=AuditLog(":memory:"), rate_limiter=RateLimiter(":memory:"),
        aggregate_tracker=AggregateSpendTracker(":memory:"),
    )
    server._actions = {}
    return server


class TestRegisterAction(unittest.TestCase):
    def test_agent_id_is_injected_into_the_schema(self):
        server = new_server()
        server.register_action(
            "safe_action", "desc", {"type": "object", "properties": {"value": {"type": "integer"}}},
            executor=lambda req: req.arguments["value"],
        )
        schema = server._tool_list()[0]["inputSchema"]
        self.assertIn("agent_id", schema["properties"])
        self.assertIn("agent_id", schema["required"])

    def test_duplicate_registration_is_rejected(self):
        server = new_server()
        server.register_action("dup", "d", {"type": "object", "properties": {}}, executor=lambda req: None)
        with self.assertRaises(ValueError):
            server.register_action("dup", "d", {"type": "object", "properties": {}}, executor=lambda req: None)


class TestToolsListAndCall(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.server = new_server()
        self.server.register_action(
            "safe_action", "A safe action", {"type": "object", "properties": {"value": {"type": "integer"}}},
            executor=self._record_and_return,
        )
        self.server.register_action(
            "wallet.transfer", "Transfer funds",
            {"type": "object", "properties": {"amount": {"type": "number"}}},
            executor=self._record_and_return,
        )

    def _record_and_return(self, request):
        self.calls.append((request.tool_name, dict(request.arguments)))
        return {"ok": True, "tool": request.tool_name}

    def test_tools_list_exposes_registered_actions(self):
        response = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in response["result"]["tools"]}
        self.assertEqual(names, {"safe_action", "wallet.transfer"})

    def test_allowed_call_actually_runs_the_real_executor(self):
        response = self.server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "safe_action", "arguments": {"agent_id": "a1", "value": 42}},
        })
        self.assertNotIn("isError", response["result"])
        self.assertEqual(self.calls, [("safe_action", {"value": 42})])

    def test_blocked_call_never_runs_the_real_executor(self):
        # Model never gets a tool to move funds directly - only this
        # gated one, which the numeric_cap here rejects outright for an
        # unknown agent (cap is 5, amount is 9999).
        response = self.server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "wallet.transfer", "arguments": {"agent_id": "brand-new", "amount": 9999}},
        })
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(self.calls, [])  # the real transfer never happened

    def test_unknown_tool_name_is_rejected(self):
        response = self.server.handle({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "nonexistent_tool", "arguments": {"agent_id": "a1"}},
        })
        self.assertIn("error", response)

    def test_missing_agent_id_is_rejected_without_running_the_executor(self):
        response = self.server.handle({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "safe_action", "arguments": {"value": 1}},
        })
        self.assertIn("error", response)
        self.assertEqual(self.calls, [])

    def test_executor_exception_is_reported_as_a_tool_error_not_a_crash(self):
        server = new_server()
        server.register_action(
            "flaky", "d", {"type": "object", "properties": {}},
            executor=lambda req: (_ for _ in ()).throw(RuntimeError("backend down")),
        )
        response = server.handle({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {"name": "flaky", "arguments": {"agent_id": "a1"}},
        })
        self.assertTrue(response["result"]["isError"])

    def test_a_different_agent_id_gets_its_own_isolated_numeric_cap_state(self):
        # Each call binds identity via the agent_id argument itself - two
        # different agent_ids don't share rate-limit/cap state.
        r1 = self.server.handle({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "wallet.transfer", "arguments": {"agent_id": "agent-x", "amount": 4}},
        })
        r2 = self.server.handle({
            "jsonrpc": "2.0", "id": 8, "method": "tools/call",
            "params": {"name": "wallet.transfer", "arguments": {"agent_id": "agent-y", "amount": 4}},
        })
        self.assertNotIn("isError", r1["result"])
        self.assertNotIn("isError", r2["result"])


class TestWarnRouting(unittest.TestCase):
    def test_on_warn_returning_false_blocks_and_never_runs_the_executor(self):
        calls = []
        server = new_server()
        server.register_action(
            "risky_action", "d", {"type": "object", "properties": {}},
            executor=lambda req: calls.append(1),
            on_warn=lambda decision: False,
        )
        response = server.handle({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "risky_action", "arguments": {"agent_id": "a1"}},
        })
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(calls, [])

    def test_on_warn_returning_true_proceeds_and_runs_the_executor(self):
        calls = []
        server = new_server()
        server.register_action(
            "risky_action", "d", {"type": "object", "properties": {}},
            executor=lambda req: calls.append(1),
            on_warn=lambda decision: True,
        )
        response = server.handle({
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "risky_action", "arguments": {"agent_id": "a1"}},
        })
        self.assertNotIn("isError", response["result"])
        self.assertEqual(calls, [1])


class TestProtocolBasics(unittest.TestCase):
    def test_initialize(self):
        server = new_server()
        response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(response["result"]["serverInfo"]["name"], "guardrail-enforced")

    def test_initialized_notification_returns_nothing(self):
        server = new_server()
        self.assertIsNone(server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_unknown_method_is_an_error(self):
        server = new_server()
        response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "nope"})
        self.assertIn("error", response)


if __name__ == "__main__":
    unittest.main()
