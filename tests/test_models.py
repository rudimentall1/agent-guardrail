import time
import unittest
from unittest.mock import patch

from guardrail.core.models import ActionRequest, Decision, GuardrailDecision, RuleMatch, Severity


class TestActionRequestId(unittest.TestCase):
    def test_request_id_is_present_and_reasonably_sized(self):
        req = ActionRequest(agent_id="a1", tool_name="wallet.transfer", arguments={"amount": 5})
        self.assertTrue(req.request_id)
        self.assertGreaterEqual(len(req.request_id), 8)

    def test_request_id_is_stable_across_repeated_access(self):
        req = ActionRequest(agent_id="a1", tool_name="wallet.transfer")
        first = req.request_id
        second = req.request_id
        self.assertEqual(first, second)

    def test_identical_requests_get_different_ids(self):
        """The bug this guards against: request_id used to be
        sha256(agent_id, tool_name, arguments, requested_at)[:16], and
        two identical back-to-back tool calls (an ordinary retry
        pattern) commonly share the same time.time() value at typical
        clock resolution - so they'd get the SAME request_id. Since
        request_id is the audit log's SQLite primary key, that meant
        INSERT OR REPLACE would silently erase the earlier decision's
        row, and confirmation/web_ui.py's pending-items dict (also keyed
        by request_id) would silently drop one of two genuinely distinct
        pending human-confirmation items.

        requested_at is passed explicitly here (not left to its
        default_factory=time.time) to force a genuine collision
        deterministically - patching time.time wouldn't work anyway,
        since the dataclass field captures a direct reference to the
        function at class-definition time, not a live lookup.
        """
        req1 = ActionRequest(agent_id="a1", tool_name="wallet.transfer",
                              arguments={"amount": 5}, requested_at=1000.0)
        req2 = ActionRequest(agent_id="a1", tool_name="wallet.transfer",
                              arguments={"amount": 5}, requested_at=1000.0)
        self.assertNotEqual(req1.request_id, req2.request_id)

    def test_many_identical_requests_with_the_same_timestamp_never_collide(self):
        ids = {
            ActionRequest(agent_id="a1", tool_name="t", arguments={"x": 1},
                          requested_at=1000.0).request_id
            for _ in range(1000)
        }
        self.assertEqual(len(ids), 1000)


class TestGuardrailDecisionSerialization(unittest.TestCase):
    def test_to_dict_includes_request_id(self):
        decision = GuardrailDecision(
            decision=Decision.ALLOW,
            matched_rules=[RuleMatch(rule="r", severity=Severity.WARN, message="m")],
            explanation=["ok"],
            agent_id="a1",
            tool_name="wallet.transfer",
            request_id="abc123",
        )
        payload = decision.to_dict()
        self.assertEqual(payload["request_id"], "abc123")


if __name__ == "__main__":
    unittest.main()
