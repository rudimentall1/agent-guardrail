"""Guardrail CLI — also the console-script entry point once installed
(`pip install .` gives you the `guardrail` command).

    guardrail check --agent a --tool wallet.transfer --args '{"amount": 5}'
    guardrail history --agent a
    guardrail policy validate policies/default.yaml
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Dict, List

from guardrail.core.models import ActionRequest
from guardrail.core.policy import Policy
from guardrail.engine import GuardrailEngine
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter


DEFAULT_POLICY_ARG = "policies/default.yaml"


def resolve_policy(policy_path: str) -> Policy:
    """Load a policy file, falling back to the copy bundled inside the
    installed package if the caller left --policy at its default value
    and there's no local policies/default.yaml (e.g. running as an
    installed console script from an arbitrary directory, rather than
    from a git clone). An explicitly-pointed-at file that's missing is
    still a hard error — no silent fallback in that case.
    """
    import os

    if os.path.exists(policy_path):
        return Policy.from_yaml_file(policy_path)
    if policy_path == DEFAULT_POLICY_ARG:
        return Policy.default()
    raise FileNotFoundError(f"Policy file not found: {policy_path}")


def build_engine(policy_path: str, audit_db: str) -> GuardrailEngine:
    policy = resolve_policy(policy_path)
    return GuardrailEngine(
        policy=policy,
        audit_log=AuditLog(audit_db),
        rate_limiter=RateLimiter(audit_db.replace(".db", "_ratelimit.db")),
    )


def _validate_policy_dict(raw: Dict[str, Any]) -> List[str]:
    """Structural + regex validation with a full list of problems, not just
    the first one — so fixing a policy file doesn't take N round trips."""
    errors: List[str] = []

    for i, p in enumerate(raw.get("argument_patterns") or []):
        label = p.get("name", f"#{i}")
        if "pattern" not in p:
            errors.append(f"argument_patterns[{label}]: missing 'pattern'")
            continue
        try:
            re.compile(p["pattern"])
        except re.error as e:
            errors.append(f"argument_patterns[{label}]: invalid regex — {e}")
        severity = str(p.get("severity", "WARN")).upper()
        if severity not in ("WARN", "BLOCK"):
            errors.append(f"argument_patterns[{label}]: severity must be WARN or BLOCK, got {p.get('severity')!r}")

    for tool, spec in (raw.get("numeric_caps") or {}).items():
        if "field" not in spec:
            errors.append(f"numeric_caps[{tool}]: missing 'field'")

    for tool, spec in (raw.get("domain_rules") or {}).items():
        if "field" not in spec:
            errors.append(f"domain_rules[{tool}]: missing 'field'")
        if spec.get("mode") not in ("allowlist", "denylist"):
            errors.append(f"domain_rules[{tool}]: mode must be 'allowlist' or 'denylist', got {spec.get('mode')!r}")

    rl = raw.get("rate_limits") or {}
    scopes = {"default": rl.get("default") or {}}
    scopes.update(rl.get("overrides") or {})
    for scope, spec in scopes.items():
        if spec and ("max_calls" not in spec or "window_seconds" not in spec):
            errors.append(f"rate_limits[{scope}]: needs both 'max_calls' and 'window_seconds'")

    return errors


def _cmd_policy_validate(args: argparse.Namespace) -> None:
    import yaml

    try:
        with open(args.policy_file, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"✗ policy file not found: {args.policy_file}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"✗ YAML syntax error in {args.policy_file}:\n  {e}", file=sys.stderr)
        sys.exit(1)

    errors = _validate_policy_dict(raw)
    if errors:
        print(f"✗ {len(errors)} problem(s) found in {args.policy_file}:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    policy = Policy.from_dict(raw)
    print(f"✓ {args.policy_file} is valid")
    print(f"  {len(policy.argument_patterns)} argument pattern(s)")
    print(f"  {len(policy.blocked_tools)} blocked tool(s)")
    print(f"  {len(policy.confirmation_required_tools)} confirmation-required tool(s)")
    print(f"  {len(policy.numeric_caps)} numeric cap(s)")
    print(f"  {len(policy.domain_rules)} domain rule(s)")
    print(f"  {len(policy.rate_limit_overrides)} rate-limit override(s)")


def _cmd_check(args: argparse.Namespace) -> None:
    try:
        arguments = json.loads(args.args)
    except json.JSONDecodeError as e:
        print(f"Invalid --args JSON: {e}", file=sys.stderr)
        sys.exit(2)

    engine = build_engine(args.policy, args.audit_db)
    request = ActionRequest(agent_id=args.agent, tool_name=args.tool, arguments=arguments)
    decision = engine.evaluate(request)
    print(json.dumps(decision.to_dict(), indent=2))
    sys.exit(0 if decision.decision.value != "BLOCK" else 1)


def _cmd_history(args: argparse.Namespace) -> None:
    engine = build_engine(args.policy, args.audit_db)
    print(json.dumps(engine.history_for_agent(args.agent, args.limit), indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardrail")
    parser.add_argument("--policy", default="policies/default.yaml", help="Policy YAML file to evaluate against")
    parser.add_argument("--audit-db", default="guardrail_audit.db")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Evaluate a single action against the policy")
    check.add_argument("--agent", required=True)
    check.add_argument("--tool", required=True)
    check.add_argument("--args", default="{}", help='JSON-encoded arguments, e.g. \'{"amount": 5}\'')
    check.set_defaults(func=_cmd_check)

    history = sub.add_parser("history", help="Show decision history for an agent")
    history.add_argument("--agent", required=True)
    history.add_argument("--limit", type=int, default=20)
    history.set_defaults(func=_cmd_history)

    policy_cmd = sub.add_parser("policy", help="Policy file utilities")
    policy_sub = policy_cmd.add_subparsers(dest="policy_command", required=True)
    validate = policy_sub.add_parser("validate", help="Check a policy file for syntax/structural errors")
    validate.add_argument("policy_file", help="Path to the policy YAML file to validate")
    validate.set_defaults(func=_cmd_policy_validate)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
