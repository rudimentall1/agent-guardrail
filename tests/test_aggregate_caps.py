import time
import unittest

from guardrail.core.models import ActionRequest, Decision
from guardrail.core.policy import AggregateCapRule, Policy
from guardrail.engine import GuardrailEngine
from guardrail.rules import find_aggregate_contributions
from guardrail.storage.aggregate_spend import AggregateSpendTracker
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter


class TestAggregateSpendTracker(unittest.TestCase):
    def test_empty_tracker_has_zero_total(self):
        tracker = AggregateSpendTracker(":memory:")
        self.assertEqual(tracker.current_total("a1", "money", 60), 0)

    def test_records_accumulate(self):
        tracker = AggregateSpendTracker(":memory:")
        tracker.record("a1", "money", 100.0, "req-1", window_seconds=60)
        tracker.record("a1", "money", 50.0, "req-2", window_seconds=60)
        self.assertEqual(tracker.current_total("a1", "money", 60), 150.0)

    def test_isolated_per_agent(self):
        tracker = AggregateSpendTracker(":memory:")
        tracker.record("a1", "money", 100.0, "req-1", window_seconds=60)
        tracker.record("a2", "money", 999.0, "req-2", window_seconds=60)
        self.assertEqual(tracker.current_total("a1", "money", 60), 100.0)

    def test_isolated_per_group(self):
        tracker = AggregateSpendTracker(":memory:")
        tracker.record("a1", "money", 100.0, "req-1", window_seconds=60)
        tracker.record("a1", "api_calls", 999.0, "req-2", window_seconds=60)
        self.assertEqual(tracker.current_total("a1", "money", 60), 100.0)

    def test_refund_removes_the_recorded_amount(self):
        tracker = AggregateSpendTracker(":memory:")
        tracker.record("a1", "money", 100.0, "req-1", window_seconds=60)
        tracker.refund("req-1")
        self.assertEqual(tracker.current_total("a1", "money", 60), 0)

    def test_refund_only_affects_its_own_request_id(self):
        tracker = AggregateSpendTracker(":memory:")
        tracker.record("a1", "money", 100.0, "req-1", window_seconds=60)
        tracker.record("a1", "money", 50.0, "req-2", window_seconds=60)
        tracker.refund("req-1")
        self.assertEqual(tracker.current_total("a1", "money", 60), 50.0)

    def test_refunding_unknown_request_id_is_a_no_op(self):
        tracker = AggregateSpendTracker(":memory:")
        tracker.record("a1", "money", 100.0, "req-1", window_seconds=60)
        tracker.refund("never-recorded")
        self.assertEqual(tracker.current_total("a1", "money", 60), 100.0)

    def test_old_entries_fall_out_of_the_window(self):
        tracker = AggregateSpendTracker(":memory:")
        # Backdate a row by inserting directly, simulating a spend from
        # well before the window.
        old_timestamp = time.time() - 1000
        tracker._conn.execute(
            "INSERT INTO spend (agent_id, group_name, amount, request_id, recorded_at) VALUES (?, ?, ?, ?, ?)",
            ("a1", "money", 500.0, "old-req", old_timestamp),
        )
        tracker._conn.commit()
        self.assertEqual(tracker.current_total("a1", "money", window_seconds=60), 0)

    def test_recording_cleans_up_rows_older_than_the_window(self):
        # Regression test for the same unbounded-growth class of bug
        # already fixed in rate_limiter.py - record() must trim rows for
        # this (agent, group) that have aged out of the window, not just
        # let them accumulate forever.
        tracker = AggregateSpendTracker(":memory:")
        old_timestamp = time.time() - 1000
        tracker._conn.execute(
            "INSERT INTO spend (agent_id, group_name, amount, request_id, recorded_at) VALUES (?, ?, ?, ?, ?)",
            ("a1", "money", 500.0, "old-req", old_timestamp),
        )
        tracker._conn.commit()
        tracker.record("a1", "money", 10.0, "new-req", window_seconds=60)
        cur = tracker._conn.execute("SELECT COUNT(*) FROM spend WHERE agent_id='a1' AND group_name='money'")
        self.assertEqual(cur.fetchone()[0], 1)  # only the new row remains


class TestFindAggregateContributions(unittest.TestCase):
    POLICY = Policy.from_dict({
        "aggregate_caps": {
            "daily_money": {
                "tools": {"wallet.transfer": "amount", "wallet.approve": "amount"},
                "window_seconds": 86400,
                "max_unknown_agent": 5,
                "max_known_agent": 1000,
            },
        },
    })

    def test_tool_in_group_contributes(self):
        req = ActionRequest(agent_id="a", tool_name="wallet.transfer", arguments={"amount": 50})
        warnings, contributions = find_aggregate_contributions(req, self.POLICY)
        self.assertEqual(warnings, [])
        self.assertEqual(contributions, [("daily_money", 50.0, self.POLICY.aggregate_caps["daily_money"])])

    def test_tool_not_in_any_group_contributes_nothing(self):
        req = ActionRequest(agent_id="a", tool_name="read_file", arguments={"amount": 50})
        warnings, contributions = find_aggregate_contributions(req, self.POLICY)
        self.assertEqual((warnings, contributions), ([], []))

    def test_missing_field_contributes_nothing_silently(self):
        req = ActionRequest(agent_id="a", tool_name="wallet.transfer", arguments={})
        warnings, contributions = find_aggregate_contributions(req, self.POLICY)
        self.assertEqual((warnings, contributions), ([], []))

    def test_non_numeric_field_warns_and_is_excluded(self):
        req = ActionRequest(agent_id="a", tool_name="wallet.transfer", arguments={"amount": "not-a-number"})
        warnings, contributions = find_aggregate_contributions(req, self.POLICY)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].rule, "aggregate_cap_invalid")
        self.assertEqual(contributions, [])

    def test_nan_field_warns_and_is_excluded(self):
        req = ActionRequest(agent_id="a", tool_name="wallet.transfer", arguments={"amount": float("nan")})
        warnings, contributions = find_aggregate_contributions(req, self.POLICY)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(contributions, [])

    def test_infinity_field_warns_and_is_excluded(self):
        req = ActionRequest(agent_id="a", tool_name="wallet.transfer", arguments={"amount": float("inf")})
        warnings, contributions = find_aggregate_contributions(req, self.POLICY)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(contributions, [])


class TestGuardrailEngineAggregateCaps(unittest.TestCase):
    POLICY = Policy.from_dict({
        "numeric_caps": {
            "wallet.transfer": {"field": "amount", "max_unknown_agent": 1000, "max_known_agent": 1000},
            "wallet.approve": {"field": "amount", "max_unknown_agent": 1000, "max_known_agent": 1000},
        },
        "aggregate_caps": {
            "daily_money": {
                "tools": {"wallet.transfer": "amount", "wallet.approve": "amount"},
                "window_seconds": 86400,
                "max_unknown_agent": 100,
                "max_known_agent": 1000,
            },
        },
        "rate_limits": {"default": {"max_calls": 1000, "window_seconds": 60}},
    })

    def _engine(self):
        return GuardrailEngine(
            policy=self.POLICY,
            audit_log=AuditLog(":memory:"),
            rate_limiter=RateLimiter(":memory:"),
            aggregate_tracker=AggregateSpendTracker(":memory:"),
        )

    def test_two_different_tools_share_one_aggregate_budget(self):
        # This is the actual gap being closed: wallet.transfer and
        # wallet.approve each have their own numeric_caps allowing up to
        # 1000 individually, but together they draw from ONE 100-unit
        # aggregate budget for an unknown agent.
        engine = self._engine()
        d1 = engine.evaluate(ActionRequest(agent_id="a1", tool_name="wallet.transfer", arguments={"amount": 60}))
        self.assertEqual(d1.decision, Decision.ALLOW)
        d2 = engine.evaluate(ActionRequest(agent_id="a1", tool_name="wallet.approve", arguments={"amount": 60}))
        # 60 (transfer) + 60 (approve) = 120 > 100 aggregate cap - BLOCKed
        # even though each individual numeric_cap (1000) is nowhere near
        # exceeded.
        self.assertEqual(d2.decision, Decision.BLOCK)
        self.assertTrue(any(r.rule == "aggregate_cap_exceeded" for r in d2.matched_rules))

    def test_a_single_tool_alone_can_still_hit_the_aggregate_cap(self):
        engine = self._engine()
        decision = engine.evaluate(ActionRequest(agent_id="a1", tool_name="wallet.transfer", arguments={"amount": 150}))
        self.assertEqual(decision.decision, Decision.BLOCK)

    def test_blocked_request_does_not_count_toward_the_aggregate_total(self):
        engine = self._engine()
        # First call exceeds the cap outright and gets BLOCKed.
        d1 = engine.evaluate(ActionRequest(agent_id="a1", tool_name="wallet.transfer", arguments={"amount": 150}))
        self.assertEqual(d1.decision, Decision.BLOCK)
        # A second, smaller call must not see any residual from the
        # BLOCKed first one - if it had been recorded anyway, this would
        # incorrectly push the running total over budget too.
        d2 = engine.evaluate(ActionRequest(agent_id="a1", tool_name="wallet.transfer", arguments={"amount": 50}))
        self.assertEqual(d2.decision, Decision.ALLOW)

    def test_error_outcome_refunds_the_provisional_spend(self):
        engine = self._engine()
        d1 = engine.evaluate(ActionRequest(agent_id="a1", tool_name="wallet.transfer", arguments={"amount": 90}))
        self.assertEqual(d1.decision, Decision.ALLOW)
        engine.record_outcome(d1.request_id, "error")

        # Budget should be back to 0 after the refund - a fresh 90 must
        # fit again.
        d2 = engine.evaluate(ActionRequest(agent_id="a1", tool_name="wallet.transfer", arguments={"amount": 90}))
        self.assertEqual(d2.decision, Decision.ALLOW)

    def test_success_outcome_keeps_the_spend_recorded(self):
        engine = self._engine()
        d1 = engine.evaluate(ActionRequest(agent_id="a1", tool_name="wallet.transfer", arguments={"amount": 90}))
        self.assertEqual(d1.decision, Decision.ALLOW)
        engine.record_outcome(d1.request_id, "success")

        d2 = engine.evaluate(ActionRequest(agent_id="a1", tool_name="wallet.transfer", arguments={"amount": 90}))
        # 90 (kept, confirmed success) + 90 = 180 > 100 cap.
        self.assertEqual(d2.decision, Decision.BLOCK)

    def test_known_agent_gets_the_looser_aggregate_cap(self):
        engine = self._engine()
        agent = "veteran"
        for _ in range(3):
            d = engine.evaluate(ActionRequest(agent_id=agent, tool_name="wallet.transfer", arguments={"amount": 1}))
            self.assertEqual(d.decision, Decision.ALLOW)
            engine.record_outcome(d.request_id, "success")

        # Now "known" (3 ALLOWs recorded) - the 1000 cap applies, not 100.
        decision = engine.evaluate(ActionRequest(agent_id=agent, tool_name="wallet.transfer", arguments={"amount": 500}))
        self.assertEqual(decision.decision, Decision.ALLOW)

    def test_window_expiry_frees_up_budget_again(self):
        engine = self._engine()
        d1 = engine.evaluate(ActionRequest(agent_id="a1", tool_name="wallet.transfer", arguments={"amount": 90}))
        self.assertEqual(d1.decision, Decision.ALLOW)

        # Directly age the recorded row past the window rather than
        # sleeping in a test.
        engine.aggregate_tracker._conn.execute(
            "UPDATE spend SET recorded_at = ? WHERE request_id = ?",
            (time.time() - 90000, d1.request_id),
        )
        engine.aggregate_tracker._conn.commit()

        d2 = engine.evaluate(ActionRequest(agent_id="a1", tool_name="wallet.transfer", arguments={"amount": 90}))
        self.assertEqual(d2.decision, Decision.ALLOW)


if __name__ == "__main__":
    unittest.main()
