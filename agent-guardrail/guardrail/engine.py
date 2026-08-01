"""GuardrailEngine: the single entry point.

    decision = engine.evaluate(request)

Pipeline: blocked-tool check -> argument-pattern checks -> numeric caps ->
domain checks -> confirmation-required check -> rate limit -> combine into
ALLOW / WARN / BLOCK -> persist to the audit log.

Every check is deterministic and traceable to a specific policy rule —
there is no statistical risk score here to argue with, on purpose.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from guardrail.core.models import ActionRequest, Decision, GuardrailDecision, RuleMatch, Severity
from guardrail.core.policy import Policy
from guardrail.rules import (
    check_argument_patterns,
    check_blocked_tools,
    check_confirmation_required,
    check_domain_rules,
    check_numeric_caps,
)
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter


class GuardrailEngine:
    def __init__(
        self,
        policy: Policy,
        audit_log: Optional[AuditLog] = None,
        rate_limiter: Optional[RateLimiter] = None,
        known_agent_threshold: int = 3,
    ):
        self.policy = policy
        self.audit_log = audit_log or AuditLog()
        self.rate_limiter = rate_limiter or RateLimiter()
        # An agent is "known" once it has this many prior recorded decisions —
        # used to relax numeric caps that are tighter for brand-new agents.
        self.known_agent_threshold = known_agent_threshold

    def _is_known_agent(self, agent_id: str) -> bool:
        counts = self.audit_log.counts_for_agent(agent_id)
        return sum(counts.values()) >= self.known_agent_threshold

    def evaluate(self, request: ActionRequest) -> GuardrailDecision:
        is_known = self._is_known_agent(request.agent_id)

        matches: List[RuleMatch] = []
        matches += check_blocked_tools(request, self.policy)
        matches += check_argument_patterns(request, self.policy)
        matches += check_numeric_caps(request, self.policy, is_known)
        matches += check_domain_rules(request, self.policy)
        matches += check_confirmation_required(request, self.policy)

        rl = self.policy.rate_limit_for(request.tool_name)
        rl_result = self.rate_limiter.check_and_record(
            request.agent_id, request.tool_name, rl.max_calls, rl.window_seconds
        )
        if not rl_result.allowed:
            matches.append(RuleMatch(
                rule="rate_limit_exceeded", severity=Severity.BLOCK,
                message=(
                    f"Agent exceeded {rl_result.limit} calls to '{request.tool_name}' "
                    f"within {rl_result.window_seconds}s"
                ),
            ))

        if any(m.severity == Severity.BLOCK for m in matches):
            decision_type = Decision.BLOCK
        elif any(m.severity == Severity.WARN for m in matches):
            decision_type = Decision.WARN
        else:
            decision_type = Decision.ALLOW

        explanation = [m.message for m in matches] or ["No policy rules matched this action"]

        decision = GuardrailDecision(
            decision=decision_type,
            matched_rules=matches,
            explanation=explanation,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            request_id=request.request_id,
        )
        self.audit_log.record_decision(request, decision)
        return decision

    def record_outcome(self, request_id: str, outcome: str) -> bool:
        """Record what actually happened when a previously-checked action ran."""
        return self.audit_log.record_outcome(request_id, outcome)

    def history_for_agent(self, agent_id: str, limit: int = 50) -> List[Dict]:
        return self.audit_log.history_for_agent(agent_id, limit)
