"""Declarative policy loading.

A Policy is authored as plain YAML (see policies/default.yaml) and loaded
here into structured, validated rule objects. This is the whole point of
the design: operators edit a config file to change what's allowed, they
never touch engine code. PyYAML is the one real dependency this project
has (see requirements.txt).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PatternRule:
    name: str
    pattern: str
    severity: str
    message: str

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.pattern)

    def matches(self, text: str) -> bool:
        return self._compiled.search(text) is not None


@dataclass
class NumericCapRule:
    tool: str
    field: str
    max_unknown_agent: Optional[float]
    max_known_agent: Optional[float]


@dataclass
class DomainRule:
    tool: str
    field: str
    mode: str  # "allowlist" | "denylist"
    domains: List[str]


@dataclass
class RateLimit:
    max_calls: int
    window_seconds: int


@dataclass
class Policy:
    blocked_tools: List[str] = field(default_factory=list)
    confirmation_required_tools: List[str] = field(default_factory=list)
    argument_patterns: List[PatternRule] = field(default_factory=list)
    numeric_caps: Dict[str, NumericCapRule] = field(default_factory=dict)
    domain_rules: Dict[str, DomainRule] = field(default_factory=dict)
    default_rate_limit: RateLimit = field(default_factory=lambda: RateLimit(60, 60))
    rate_limit_overrides: Dict[str, RateLimit] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        argument_patterns = [
            PatternRule(
                name=p["name"],
                pattern=p["pattern"],
                severity=p.get("severity", "WARN").upper(),
                message=p.get("message", p["name"]),
            )
            for p in (data.get("argument_patterns") or [])
        ]

        numeric_caps = {
            tool: NumericCapRule(
                tool=tool,
                field=spec["field"],
                max_unknown_agent=spec.get("max_unknown_agent"),
                max_known_agent=spec.get("max_known_agent"),
            )
            for tool, spec in (data.get("numeric_caps") or {}).items()
        }

        domain_rules = {
            tool: DomainRule(
                tool=tool,
                field=spec["field"],
                mode=spec.get("mode", "denylist"),
                domains=[d.lower() for d in spec.get("domains", [])],
            )
            for tool, spec in (data.get("domain_rules") or {}).items()
        }

        rl = data.get("rate_limits") or {}
        default_spec = rl.get("default") or {"max_calls": 60, "window_seconds": 60}
        default_rate_limit = RateLimit(default_spec["max_calls"], default_spec["window_seconds"])
        rate_limit_overrides = {
            tool: RateLimit(spec["max_calls"], spec["window_seconds"])
            for tool, spec in (rl.get("overrides") or {}).items()
        }

        return cls(
            blocked_tools=list(data.get("blocked_tools") or []),
            confirmation_required_tools=list(data.get("confirmation_required_tools") or []),
            argument_patterns=argument_patterns,
            numeric_caps=numeric_caps,
            domain_rules=domain_rules,
            default_rate_limit=default_rate_limit,
            rate_limit_overrides=rate_limit_overrides,
        )

    @classmethod
    def from_yaml_file(cls, path: str) -> "Policy":
        import yaml  # imported lazily so the rest of the engine has no hard dependency on it

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data or {})

    @classmethod
    def default(cls) -> "Policy":
        """Load the copy of policies/default.yaml bundled inside the
        installed package. Used as a fallback when running as an
        installed console script (pip install) from a directory that has
        no local `policies/default.yaml` of its own — see
        guardrail/__main__.py and guardrail/mcp_server.py.
        """
        import yaml
        from importlib.resources import files

        resource = files("guardrail").joinpath("policies", "default.yaml")
        with resource.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data or {})

    def rate_limit_for(self, tool_name: str) -> RateLimit:
        return self.rate_limit_overrides.get(tool_name, self.default_rate_limit)
