"""Persistent audit log backed by SQLite.

Every decision Guardrail makes is recorded here: which agent, which tool,
what arguments, what decision, why, and — once available — what actually
happened when the action ran. This is real, queryable history (`SELECT *
FROM decisions WHERE agent_id = ? AND decision = 'BLOCK'`), which is what
a security review actually needs, not a demo placeholder.
"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Dict, List

from guardrail.core.models import ActionRequest, GuardrailDecision


class AuditLog:
    def __init__(self, db_path: str = "guardrail_audit.db"):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                request_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                arguments TEXT NOT NULL,
                decision TEXT NOT NULL,
                matched_rules TEXT NOT NULL,
                explanation TEXT NOT NULL,
                created_at REAL NOT NULL,
                outcome TEXT,
                outcome_recorded_at REAL
            )
            """
        )
        self._conn.commit()

    def record_decision(self, request: ActionRequest, decision: GuardrailDecision) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO decisions
                (request_id, agent_id, tool_name, arguments, decision, matched_rules, explanation, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision.request_id,
                decision.agent_id,
                decision.tool_name,
                json.dumps(request.arguments, default=str),
                decision.decision.value,
                json.dumps([m.rule for m in decision.matched_rules]),
                json.dumps(decision.explanation),
                decision.created_at,
            ),
        )
        self._conn.commit()

    def record_outcome(self, request_id: str, outcome: str) -> bool:
        cur = self._conn.execute(
            "UPDATE decisions SET outcome=?, outcome_recorded_at=? WHERE request_id=?",
            (outcome, time.time(), request_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def history_for_agent(self, agent_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT request_id, tool_name, decision, created_at, outcome FROM decisions "
            "WHERE agent_id=? ORDER BY created_at DESC LIMIT ?",
            (agent_id, limit),
        )
        cols = ["request_id", "tool_name", "decision", "created_at", "outcome"]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def counts_for_agent(self, agent_id: str) -> Dict[str, int]:
        cur = self._conn.execute(
            "SELECT decision, COUNT(*) FROM decisions WHERE agent_id=? GROUP BY decision",
            (agent_id,),
        )
        counts = {"ALLOW": 0, "WARN": 0, "BLOCK": 0}
        for decision, count in cur.fetchall():
            counts[decision] = count
        return counts

    def close(self) -> None:
        self._conn.close()
