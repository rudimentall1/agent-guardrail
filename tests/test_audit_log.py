import unittest

from guardrail.core.models import ActionRequest, Decision, GuardrailDecision
from guardrail.storage.audit import AuditLog


class TestAuditLogHistoryLimit(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(":memory:")
        for i in range(20):
            request = ActionRequest(agent_id="a1", tool_name="t", arguments={})
            decision = GuardrailDecision(
                decision=Decision.ALLOW, matched_rules=[], explanation=[],
                agent_id="a1", tool_name="t", request_id=request.request_id,
            )
            self.log.record_decision(request, decision)

    def test_default_limit(self):
        history = self.log.history_for_agent("a1")
        self.assertLessEqual(len(history), 50)
        self.assertEqual(len(history), 20)

    def test_explicit_limit_respected(self):
        history = self.log.history_for_agent("a1", limit=5)
        self.assertEqual(len(history), 5)

    def test_negative_limit_does_not_return_everything_unbounded(self):
        """Regression test for Finding 7: SQLite's LIMIT -1 specifically
        means 'no limit at all' (confirmed empirically). Before this
        fix, a caller passing limit=-1 through mcp_server.py's
        guardrail_agent_history tool (or the CLI's --limit flag) got an
        agent's ENTIRE audit history in one response, no matter how
        large. limit must be clamped to a sane positive range
        regardless of what a caller requests."""
        history = self.log.history_for_agent("a1", limit=-1)
        self.assertLessEqual(len(history), AuditLog.MAX_HISTORY_LIMIT)
        self.assertGreater(len(history), 0)  # clamped to >=1, not silently empty

    def test_absurdly_large_limit_is_capped(self):
        history = self.log.history_for_agent("a1", limit=999_999_999)
        self.assertLessEqual(len(history), AuditLog.MAX_HISTORY_LIMIT)

    def test_zero_limit_is_clamped_to_at_least_one(self):
        history = self.log.history_for_agent("a1", limit=0)
        self.assertGreaterEqual(len(history), 1)


if __name__ == "__main__":
    unittest.main()
