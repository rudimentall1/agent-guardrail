"""Core domain models for Guardrail.

Zero external dependencies (stdlib only), so the engine can be embedded in
any Python agent codebase without pulling in extra requirements. PyYAML is
only used at policy-loading time (guardrail/core/policy.py), not here.
"""
from __future__ import annotations

import hashlib
import json
import time
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

    @property
    def request_id(self) -> str:
        raw = (
            f"{self.agent_id}:{self.tool_name}:"
            f"{json.dumps(self.arguments, sort_keys=True, default=str)}:{self.requested_at}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


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
