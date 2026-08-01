import unittest

from guardrail.core.policy import Policy
from guardrail.decorator import BlockedActionError, enforce
from guardrail.engine import GuardrailEngine
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter

TEST_POLICY = Policy.from_dict({
    "confirmation_required_tools": ["risky_action"],
    "numeric_caps": {
        "wallet.transfer": {"field": "amount", "max_unknown_agent": 5, "max_known_agent": 1000},
    },
})


def new_engine() -> GuardrailEngine:
    return GuardrailEngine(policy=TEST_POLICY, audit_log=AuditLog(":memory:"), rate_limiter=RateLimiter(":memory:"))


class TestEnforceDecorator(unittest.TestCase):
    def test_allowed_call_executes_normally(self):
        engine = new_engine()
        calls = []

        @enforce(engine, tool_name="safe_action")
        def do_thing(agent_id: str, value: int):
            calls.append(value)
            return value * 2

        result = do_thing(agent_id="a", value=21)
        self.assertEqual(result, 42)
        self.assertEqual(calls, [21])

    def test_blocked_call_never_executes_the_wrapped_function(self):
        engine = new_engine()
        calls = []

        @enforce(engine, tool_name="wallet.transfer")
        def transfer(agent_id: str, amount: float):
            calls.append(amount)  # should never run
            return "sent"

        with self.assertRaises(BlockedActionError):
            transfer(agent_id="brand-new", amount=9999)
        self.assertEqual(calls, [])  # the real side effect never happened

    def test_missing_agent_id_raises_type_error(self):
        engine = new_engine()

        @enforce(engine, tool_name="safe_action")
        def do_thing(value: int):
            return value

        with self.assertRaises(TypeError):
            do_thing(value=1)

    def test_warn_without_callback_allows_execution(self):
        engine = new_engine()
        calls = []

        @enforce(engine, tool_name="risky_action")
        def do_risky(agent_id: str):
            calls.append(True)
            return "done"

        result = do_risky(agent_id="a")
        self.assertEqual(result, "done")
        self.assertEqual(calls, [True])

    def test_warn_with_rejecting_callback_blocks_execution(self):
        engine = new_engine()
        calls = []

        @enforce(engine, tool_name="risky_action", on_warn=lambda decision: False)
        def do_risky(agent_id: str):
            calls.append(True)
            return "done"

        with self.assertRaises(BlockedActionError):
            do_risky(agent_id="a")
        self.assertEqual(calls, [])

    def test_outcome_recorded_on_success_and_error(self):
        engine = new_engine()

        @enforce(engine, tool_name="safe_action")
        def ok(agent_id: str):
            return "fine"

        @enforce(engine, tool_name="safe_action")
        def boom(agent_id: str):
            raise RuntimeError("kaboom")

        ok(agent_id="a")
        with self.assertRaises(RuntimeError):
            boom(agent_id="a")

        history = engine.history_for_agent("a")
        outcomes = {h["outcome"] for h in history}
        self.assertIn("success", outcomes)
        self.assertIn("error", outcomes)


if __name__ == "__main__":
    unittest.main()
