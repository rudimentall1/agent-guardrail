"""Deterministic rule evaluators.

Every function here answers a yes/no question against explicit policy
config — no statistical scoring, no mock data, no guesswork. A rule either
matches or it doesn't, and if it matches you can point to exactly which
line of the policy file caused it. That's the whole design philosophy:
predictable, auditable, boring in the best sense.
"""
from __future__ import annotations

import json
import math
from typing import List, Optional
from urllib.parse import urlparse

from guardrail.core.models import ActionRequest, RuleMatch, Severity
from guardrail.core.policy import Policy


def check_blocked_tools(request: ActionRequest, policy: Policy) -> List[RuleMatch]:
    if request.tool_name in policy.blocked_tools:
        return [RuleMatch(
            rule="blocked_tool", severity=Severity.BLOCK,
            message=f"Tool '{request.tool_name}' is blocked by policy",
        )]
    return []


def check_confirmation_required(request: ActionRequest, policy: Policy) -> List[RuleMatch]:
    if request.tool_name in policy.confirmation_required_tools:
        return [RuleMatch(
            rule="confirmation_required", severity=Severity.WARN,
            message=f"Tool '{request.tool_name}' always requires human confirmation",
        )]
    return []


def check_argument_patterns(request: ActionRequest, policy: Policy) -> List[RuleMatch]:
    serialized = json.dumps(request.arguments, default=str)
    matches: List[RuleMatch] = []
    for rule in policy.argument_patterns:
        if rule.matches(serialized):
            severity = Severity.BLOCK if rule.severity == "BLOCK" else Severity.WARN
            matches.append(RuleMatch(rule=f"pattern:{rule.name}", severity=severity, message=rule.message))
    return matches


def check_numeric_caps(request: ActionRequest, policy: Policy, is_known_agent: bool) -> List[RuleMatch]:
    cap = policy.numeric_caps.get(request.tool_name)
    if not cap:
        return []

    value = request.arguments.get(cap.field)
    if value is None:
        return []

    try:
        value = float(value)
    except (TypeError, ValueError):
        return [RuleMatch(
            rule="numeric_cap_invalid", severity=Severity.WARN,
            message=f"Field '{cap.field}' on '{request.tool_name}' is not numeric",
        )]

    if math.isnan(value) or math.isinf(value):
        # float('nan') > limit and float('nan') < limit are both False in
        # Python - a plain comparison silently lets a NaN value through
        # every cap untouched. Confirmed this is reachable in practice:
        # mcp_server.py's json.loads() accepts a bare `NaN` literal in the
        # incoming MCP message by default (a non-standard but enabled-by-
        # default extension of Python's json module), so this isn't a
        # theoretical concern - a malformed or malicious tool-call
        # argument reaches this exact comparison. (Infinity IS correctly
        # caught by `value > limit` below; NaN specifically is not.)
        return [RuleMatch(
            rule="numeric_cap_invalid", severity=Severity.WARN,
            message=f"Field '{cap.field}' on '{request.tool_name}' must be a finite number (got NaN or Infinity)",
        )]

    limit = cap.max_known_agent if is_known_agent else cap.max_unknown_agent
    if limit is not None and value > limit:
        return [RuleMatch(
            rule="numeric_cap_exceeded", severity=Severity.BLOCK,
            message=(
                f"{cap.field}={value} exceeds cap {limit} for '{request.tool_name}' "
                f"({'known' if is_known_agent else 'unknown'} agent)"
            ),
        )]
    return []


def _extract_domain(value: str) -> Optional[str]:
    value = value.strip()
    if "@" in value and "://" not in value:
        return value.split("@")[-1].lower() or None
    parsed = urlparse(value if "://" in value else f"//{value}")
    return parsed.hostname.lower() if parsed.hostname else None


def check_domain_rules(request: ActionRequest, policy: Policy) -> List[RuleMatch]:
    rule = policy.domain_rules.get(request.tool_name)
    if not rule:
        return []

    raw_value = request.arguments.get(rule.field)
    if not raw_value:
        return []

    domain = _extract_domain(str(raw_value))
    if domain is None:
        return []

    if rule.mode == "denylist":
        if domain in rule.domains:
            return [RuleMatch(
                rule="domain_denied", severity=Severity.BLOCK,
                message=f"Domain '{domain}' is on the deny-list for '{request.tool_name}'",
            )]
        return []

    # allowlist mode: an empty list means "not enforced yet", not "deny everything"
    if rule.domains and domain not in rule.domains:
        return [RuleMatch(
            rule="domain_not_allowed", severity=Severity.BLOCK,
            message=f"Domain '{domain}' is not on the allow-list for '{request.tool_name}'",
        )]
    return []
