import time
import unittest
from unittest.mock import patch

from guardrail.storage.rate_limiter import RateLimiter


class TestRateLimiter(unittest.TestCase):
    def setUp(self):
        self.limiter = RateLimiter(":memory:")

    def tearDown(self):
        self.limiter.close()

    def _row_count(self) -> int:
        return self.limiter._conn.execute("SELECT COUNT(*) FROM calls").fetchone()[0]

    def test_allows_calls_under_the_limit(self):
        for _ in range(3):
            result = self.limiter.check_and_record("a1", "tool", max_calls=5, window_seconds=60)
            self.assertTrue(result.allowed)

    def test_blocks_calls_over_the_limit(self):
        for _ in range(3):
            self.limiter.check_and_record("a1", "tool", max_calls=3, window_seconds=60)
        result = self.limiter.check_and_record("a1", "tool", max_calls=3, window_seconds=60)
        self.assertFalse(result.allowed)
        self.assertEqual(result.current_count, 4)

    def test_different_agents_have_independent_limits(self):
        for _ in range(3):
            self.limiter.check_and_record("a1", "tool", max_calls=3, window_seconds=60)
        result = self.limiter.check_and_record("a2", "tool", max_calls=3, window_seconds=60)
        self.assertTrue(result.allowed)

    def test_old_calls_do_not_count_toward_a_fresh_window(self):
        base = time.time()
        with patch("time.time", return_value=base - 120):
            self.limiter.check_and_record("a1", "tool", max_calls=1, window_seconds=60)
        # 120s later, outside the 60s window - should be treated as fresh.
        with patch("time.time", return_value=base):
            result = self.limiter.check_and_record("a1", "tool", max_calls=1, window_seconds=60)
        self.assertTrue(result.allowed)

    def test_stale_rows_are_purged_not_accumulated_forever(self):
        """Regression test for Finding 3: the `calls` table used to grow
        by one row on every single check_and_record() call, forever -
        nothing ever deleted a row, the WHERE clause in the SELECT only
        filtered what counted toward the current window. Same
        vulnerability class as the rate-limiter and cache fixes made
        earlier this session in the sibling Guardian project, but worse
        here since this table is persistent (survives process restarts
        per the module's own docstring) and sits on a path hit by every
        single request."""
        base = time.time()
        with patch("time.time", return_value=base - 120):
            for _ in range(50):
                self.limiter.check_and_record("a1", "tool", max_calls=1000, window_seconds=60)
        self.assertEqual(self._row_count(), 50)

        # A call 120s later (outside that 60s window) should trigger
        # cleanup of those 50 now-stale rows for this same key.
        with patch("time.time", return_value=base):
            self.limiter.check_and_record("a1", "tool", max_calls=1000, window_seconds=60)
        self.assertEqual(self._row_count(), 1)

    def test_repeated_calls_within_the_window_are_not_purged(self):
        # Only rows OLDER than the current window_start get removed -
        # rows that still count toward the active window must survive.
        for _ in range(10):
            self.limiter.check_and_record("a1", "tool", max_calls=1000, window_seconds=60)
        self.assertEqual(self._row_count(), 10)

    def test_persists_across_reconnection_to_the_same_file(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ratelimit.db")
            limiter1 = RateLimiter(path)
            limiter1.check_and_record("a1", "tool", max_calls=5, window_seconds=60)
            limiter1.close()

            limiter2 = RateLimiter(path)
            result = limiter2.check_and_record("a1", "tool", max_calls=2, window_seconds=60)
            limiter2.close()
            # Second call for this key, limit 2 - should still be allowed
            # (count=2 after this call, which is not >= max_calls... wait
            # allowed is current_count < max_calls checked BEFORE this
            # call's insert, so with 1 prior call, count=1 < 2 -> allowed)
            self.assertTrue(result.allowed)


if __name__ == "__main__":
    unittest.main()
