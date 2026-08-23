import unittest

from guardrail.core.models import ActionRequest, Decision
from guardrail.core.policy import Policy
from guardrail.engine import GuardrailEngine
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter

TEST_POLICY = Policy.from_dict({
    "blocked_tools": ["nuke_everything"],
    "confirmation_required_tools": ["send_email"],
    "argument_patterns": [
        {"name": "dangerous_rm", "pattern": r'rm\s+-rf\s+/(?=\s|"|$)', "severity": "BLOCK", "message": "destructive"},
    ],
    "numeric_caps": {
        "wallet.transfer": {"field": "amount", "max_unknown_agent": 5, "max_known_agent": 1000},
    },
    "rate_limits": {"default": {"max_calls": 3, "window_seconds": 60}},
})


def new_engine(known_agent_threshold: int = 3) -> GuardrailEngine:
    return GuardrailEngine(
        policy=TEST_POLICY,
        audit_log=AuditLog(":memory:"),
        rate_limiter=RateLimiter(":memory:"),
        known_agent_threshold=known_agent_threshold,
    )


class TestGuardrailEngine(unittest.TestCase):
    def test_blocked_tool_is_blocked(self):
        engine = new_engine()
        decision = engine.evaluate(ActionRequest(agent_id="a", tool_name="nuke_everything"))
        self.assertEqual(decision.decision, Decision.BLOCK)

    def test_clean_action_is_allowed(self):
        engine = new_engine()
        decision = engine.evaluate(ActionRequest(agent_id="a", tool_name="read_file", arguments={"path": "/tmp/x"}))
        self.assertEqual(decision.decision, Decision.ALLOW)

    def test_confirmation_required_tool_produces_warn(self):
        engine = new_engine()
        decision = engine.evaluate(ActionRequest(agent_id="a", tool_name="send_email", arguments={}))
        self.assertEqual(decision.decision, Decision.WARN)

    def test_destructive_pattern_blocks_regardless_of_tool(self):
        engine = new_engine()
        decision = engine.evaluate(ActionRequest(agent_id="a", tool_name="execute_code",
                                                   arguments={"command": "rm -rf /"}))
        self.assertEqual(decision.decision, Decision.BLOCK)

    def test_unknown_agent_hits_tighter_numeric_cap(self):
        engine = new_engine()
        decision = engine.evaluate(ActionRequest(agent_id="brand-new", tool_name="wallet.transfer",
                                                   arguments={"amount": 50}))
        self.assertEqual(decision.decision, Decision.BLOCK)

    def test_known_agent_gets_looser_cap(self):
        engine = new_engine(known_agent_threshold=1)
        # First call establishes history (any clean action).
        engine.evaluate(ActionRequest(agent_id="veteran", tool_name="read_file", arguments={"path": "/tmp"}))
        decision = engine.evaluate(ActionRequest(agent_id="veteran", tool_name="wallet.transfer",
                                                   arguments={"amount": 50}))
        self.assertEqual(decision.decision, Decision.ALLOW)

    def test_blocked_calls_do_not_earn_known_agent_status(self):
        # Regression test: "known" status used to be earned by
        # sum(counts.values()) - every recorded decision, BLOCK included.
        # That made it free: calling a guaranteed-BLOCK tool
        # `known_agent_threshold` times cost nothing (a blocked action
        # never executes) and unlocked the much higher
        # max_known_agent numeric cap on the very next real call. Only
        # ALLOW should build that status now.
        engine = new_engine(known_agent_threshold=3)
        attacker = "farms-block-status"
        for _ in range(3):
            decision = engine.evaluate(ActionRequest(agent_id=attacker, tool_name="nuke_everything"))
            self.assertEqual(decision.decision, Decision.BLOCK)

        # Same numeric cap boundary as test_unknown_agent_hits_tighter_
        # numeric_cap - if "known" status had been earned for free above,
        # this would incorrectly ALLOW at the max_known_agent=1000 cap.
        decision = engine.evaluate(ActionRequest(agent_id=attacker, tool_name="wallet.transfer",
                                                   arguments={"amount": 50}))
        self.assertEqual(decision.decision, Decision.BLOCK)

    def test_warn_only_history_does_not_earn_known_agent_status(self):
        # WARN is the tool flagging something worth a second look, not a
        # track record of clean use - it must not count toward "known"
        # any more than BLOCK does.
        engine = new_engine(known_agent_threshold=3)
        agent = "warn-only-history"
        for _ in range(3):
            decision = engine.evaluate(ActionRequest(agent_id=agent, tool_name="send_email", arguments={}))
            self.assertEqual(decision.decision, Decision.WARN)

        decision = engine.evaluate(ActionRequest(agent_id=agent, tool_name="wallet.transfer",
                                                   arguments={"amount": 50}))
        self.assertEqual(decision.decision, Decision.BLOCK)

    def test_rate_limit_blocks_after_threshold(self):
        engine = new_engine()
        agent = "spammer"
        decisions = [
            engine.evaluate(ActionRequest(agent_id=agent, tool_name="read_file", arguments={"path": f"/tmp/{i}"}))
            for i in range(5)
        ]
        # Policy allows 3 calls per window; the 4th and 5th should be rate-limited.
        self.assertEqual(decisions[0].decision, Decision.ALLOW)
        self.assertEqual(decisions[1].decision, Decision.ALLOW)
        self.assertEqual(decisions[2].decision, Decision.ALLOW)
        self.assertEqual(decisions[3].decision, Decision.BLOCK)
        self.assertTrue(any(m.rule == "rate_limit_exceeded" for m in decisions[3].matched_rules))

    def test_outcome_is_recorded_and_retrievable(self):
        engine = new_engine()
        decision = engine.evaluate(ActionRequest(agent_id="a", tool_name="read_file", arguments={"path": "/tmp"}))
        ok = engine.record_outcome(decision.request_id, "success")
        self.assertTrue(ok)
        history = engine.history_for_agent("a")
        self.assertEqual(history[0]["outcome"], "success")

    def test_decision_serializes_cleanly(self):
        engine = new_engine()
        decision = engine.evaluate(ActionRequest(agent_id="a", tool_name="read_file", arguments={"path": "/tmp"}))
        payload = decision.to_dict()
        for key in ("decision", "matched_rules", "explanation", "agent_id", "tool_name", "request_id"):
            self.assertIn(key, payload)


if __name__ == "__main__":
    unittest.main()
