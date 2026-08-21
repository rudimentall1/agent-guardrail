"""
attestation.py — turns a GuardrailDecision into a signed OAA token.

This is what makes agent-guardrail's decisions independently
verifiable by a third party, not just logged in this process's own
SQLite audit log. See oaa.py for the vendored OAA reference
implementation, and https://github.com/rudimentall1/open-agent-attestation
for the spec.
"""

from __future__ import annotations

import hashlib
import json

from guardrail.core.models import GuardrailDecision
from .oaa import issue


def _policy_fingerprint(policy: dict) -> str:
    """A stable hash of the policy that produced a decision - not the
    policy itself (which may be sensitive/proprietary), just its
    fingerprint. Anyone disputing a decision can confirm which policy
    version was active without you disclosing your actual rules."""
    canonical = json.dumps(policy, sort_keys=True, default=str).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def decision_to_oaa_token(
    decision: GuardrailDecision,
    policy: dict,
    *,
    issuer: str,
    private_key_pem: bytes,
    ttl_seconds: int | None = None,
) -> str:
    """Sign a GuardrailDecision as an OAA token.

    `issuer` should identify this deployment (e.g. a URL for your
    instance, or the GitHub repo if you haven't deployed one).
    `private_key_pem` - generate once with oaa.generate_keypair() and
    keep it; the public half is what you publish so others can verify.
    `ttl_seconds` - forwarded to oaa.issue(); defaults to that
    function's own default (15 minutes) if not given here.
    """
    reason = "; ".join(m.message for m in decision.matched_rules) or "no rules matched"

    kwargs = {}
    if ttl_seconds is not None:
        kwargs["ttl_seconds"] = ttl_seconds

    return issue(
        issuer=issuer,
        subject=decision.agent_id,
        decision=decision.decision.value,
        action=f"tool_call:{decision.tool_name}",
        reason=reason,
        policy_ref=_policy_fingerprint(policy),
        private_key_pem=private_key_pem,
        **kwargs,
    )