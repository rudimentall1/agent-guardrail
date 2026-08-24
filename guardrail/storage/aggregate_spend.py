"""Sliding-window aggregate spend tracker, backed by SQLite.

Real and persistent — same storage philosophy as
``storage/rate_limiter.py``: rows survive process restarts when given a
file path, in-memory for tests via ``:memory:``.

The difference from the rate limiter: this sums a *value* (an amount)
across a *group of tools*, not just counts calls to one tool. This is
what closes a real gap in the per-tool ``numeric_caps`` design: a policy
can cap ``wallet.transfer`` at 1000/day and ``wallet.approve`` at
1000/day independently, but an agent using both isn't capped at 1000/day
*combined* — it can move up to 2000/day by splitting across the two
tools. An ``aggregate_caps`` group (see ``core/policy.py`` and
``rules.py``) shares one running total across every tool listed in it.

Only *confirmed* spend counts. A request is recorded at check time, but
only the amount that the engine actually decided not to BLOCK — the
engine calls ``record()`` for a non-BLOCK decision, and ``refund()`` if
the caller later reports (via ``GuardrailEngine.record_outcome()``) that
the wrapped action didn't actually succeed after all. This mirrors the
same lesson already learned the hard way in a sibling project
(``agentic-wallet-guardian-v3``'s ``CapabilityRegistry``): a daily-spend
tracker that counts every *attempted* check, rather than every action
that actually went through, lets an agent burn through its budget on
actions that never really executed - or, worse here, get needlessly
blocked once its recorded (but never real) spend exceeds the cap. If an
integration never calls ``record_outcome()`` at all (e.g. the advisory
MCP server, not the enforceable ``@enforce()`` decorator - see
``decorator.py``), a recorded amount simply stays recorded permanently:
still an improvement over counting BLOCKed calls too, but this feature's
real enforcement guarantee depends on being paired with the decorator,
same as guardrail's other genuinely-enforced-vs-merely-advisory
distinction.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass


@dataclass
class AggregateSpendResult:
    allowed: bool
    current_total: float
    projected_total: float
    limit: float
    window_seconds: int


class AggregateSpendTracker:
    def __init__(self, db_path: str = ":memory:"):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS spend (
                agent_id TEXT NOT NULL,
                group_name TEXT NOT NULL,
                amount REAL NOT NULL,
                request_id TEXT NOT NULL,
                recorded_at REAL NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_spend_agent_group ON spend(agent_id, group_name, recorded_at)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_spend_request_id ON spend(request_id)"
        )
        self._conn.commit()

    def current_total(self, agent_id: str, group_name: str, window_seconds: int) -> float:
        """Confirmed spend for (agent_id, group_name) within the last
        window_seconds. Read-only — does not record anything; the engine
        calls this once per candidate group while deciding, then calls
        ``record()`` separately only for the group(s) whose request ends
        up not BLOCKed."""
        window_start = time.time() - window_seconds
        cur = self._conn.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM spend WHERE agent_id=? AND group_name=? AND recorded_at>=?",
            (agent_id, group_name, window_start),
        )
        return cur.fetchone()[0]

    def record(self, agent_id: str, group_name: str, amount: float, request_id: str,
               window_seconds: int) -> None:
        now = time.time()
        self._conn.execute(
            "INSERT INTO spend (agent_id, group_name, amount, request_id, recorded_at) VALUES (?, ?, ?, ?, ?)",
            (agent_id, group_name, amount, request_id, now),
        )
        # Same unbounded-growth fix already applied in rate_limiter.py -
        # bounds row growth for exactly the case that matters (a key
        # recorded against repeatedly); a key that goes silent leaves a
        # small bounded residual until it's recorded against again.
        window_start = now - window_seconds
        self._conn.execute(
            "DELETE FROM spend WHERE agent_id=? AND group_name=? AND recorded_at<?",
            (agent_id, group_name, window_start),
        )
        self._conn.commit()

    def refund(self, request_id: str) -> None:
        """Removes every row recorded for this request_id - called when
        the caller reports (via GuardrailEngine.record_outcome()) that
        the action this request represented did not actually succeed, so
        its provisionally-recorded spend should not count against the
        agent's ongoing total after all."""
        self._conn.execute("DELETE FROM spend WHERE request_id=?", (request_id,))
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
