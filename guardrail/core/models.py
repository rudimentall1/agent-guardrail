"""Core domain models for Guardrail.

Zero external dependencies (stdlib only), so the engine can be embedded in
any Python agent codebase without pulling in extra requirements. PyYAML is
only used at policy-loading time (guardrail/core/policy.py), not here.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class Severity(str, Enum):
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass
class ActionRequest:
    """A proposed tool call an agent wants to make, before it happens."""

    agent_id: str
    tool_name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    requested_at: float = field(default_factory=time.time)
    # A request's identity must be independent of its content and
    # timestamp: it's the primary key for the audit log (a collision
    # silently erases the earlier decision's row via INSERT OR REPLACE)
    # and the key for pending human-confirmation items in
    # confirmation/web_ui.py (a collision there silently drops one of
    # two genuinely distinct pending actions from the reviewer's queue,
    # and resolving the survivor resolves both). Two identical back-to-
    # back tool calls - an ordinary retry pattern - are exactly the case
    # a content+timestamp hash collides on: requested_at is time.time(),
    # which produces identical values on a large fraction of consecutive
    # calls (measured ~37% in this environment) at typical clock
    # resolution. A random id has no such failure mode regardless of how
    # fast or how identical consecutive requests are.
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])


@dataclass
class RuleMatch:
    rule: str
    severity: Severity
    message: str


@dataclass
class GuardrailDecision:
    decision: Decision
    matched_rules: List[RuleMatch]
    explanation: List[str]
    agent_id: str
    tool_name: str
    request_id: str
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "matched_rules": [
                {"rule": m.rule, "severity": m.severity.value, "message": m.message}
                for m in self.matched_rules
            ],
            "explanation": self.explanation,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "request_id": self.request_id,
            "created_at": self.created_at,
        }
