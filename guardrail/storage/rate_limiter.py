"""Sliding-window rate limiter backed by SQLite.

Real and persistent — counts are stored on disk (or in-memory for tests
via ``:memory:``) and survive process restarts when given a file path.
Each call is timestamped; a limit triggers when the count of calls for
(agent_id, tool_name) inside the configured window meets or exceeds the
configured maximum.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    allowed: bool
    current_count: int
    limit: int
    window_seconds: int


class RateLimiter:
    def __init__(self, db_path: str = ":memory:"):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS calls (
                agent_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                called_at REAL NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_calls_agent_tool ON calls(agent_id, tool_name, called_at)"
        )
        self._conn.commit()

    def check_and_record(self, agent_id: str, tool_name: str, max_calls: int, window_seconds: int) -> RateLimitResult:
        now = time.time()
        window_start = now - window_seconds

        cur = self._conn.execute(
            "SELECT COUNT(*) FROM calls WHERE agent_id=? AND tool_name=? AND called_at>=?",
            (agent_id, tool_name, window_start),
        )
        current_count = cur.fetchone()[0]
        allowed = current_count < max_calls

        # Record the attempt regardless of outcome, so the window reflects
        # actual call volume rather than only successful ones.
        self._conn.execute(
            "INSERT INTO calls (agent_id, tool_name, called_at) VALUES (?, ?, ?)",
            (agent_id, tool_name, now),
        )
        # Without this, `calls` grows by one row on every single call,
        # forever - the WHERE clause above only filters what counts
        # toward the current window, it never removes anything. Piggy-
        # backing the cleanup on the same round trip, scoped to this
        # (agent_id, tool_name) pair, bounds row growth for exactly the
        # case that matters: a key called repeatedly. A key that goes
        # silent leaves a small bounded residual (its last window's
        # worth of rows) until it's called again, which then cleans it.
        self._conn.execute(
            "DELETE FROM calls WHERE agent_id=? AND tool_name=? AND called_at<?",
            (agent_id, tool_name, window_start),
        )
        self._conn.commit()

        return RateLimitResult(
            allowed=allowed, current_count=current_count + 1,
            limit=max_calls, window_seconds=window_seconds,
        )

    def close(self) -> None:
        self._conn.close()
