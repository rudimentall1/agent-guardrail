"""
example_oaa_attestation.py — shows a GuardrailDecision becoming a
signed, independently verifiable OAA token.

Run: python3 examples/example_oaa_attestation.py
"""
import sys
import yaml

sys.path.insert(0, ".")

from guardrail.core.models import ActionRequest
from guardrail.core.policy import Policy
from guardrail.engine import GuardrailEngine
from guardrail.attestation import decision_to_oaa_token
from guardrail.oaa import generate_keypair, verify

with open("policies/default.yaml") as f:
    raw_policy = yaml.safe_load(f)
policy = Policy.from_dict(raw_policy)
engine = GuardrailEngine(policy)

request = ActionRequest(
    agent_id="agent-42",
    tool_name="wallet.transfer",
    arguments={"amount": 9999, "to": "0xabc"},
)
decision = engine.evaluate(request)
print(f"decision: {decision.decision.value}")

# In real use, generate this once and keep the private key - don't
# regenerate per decision.
private_key, public_key = generate_keypair()

token = decision_to_oaa_token(
    decision,
    raw_policy,
    issuer="https://github.com/rudimentall1/agent-guardrail",
    private_key_pem=private_key,
)
print(f"\nOAA token:\n{token}")

# This is the part that matters: verification needs ONLY the public
# key - no access to this process, its database, or its audit log.
result = verify(token, public_key)
print(f"\nverified by a third party:")
print(f"  decision: {result.decision}")
print(f"  action:   {result.action}")
print(f"  reason:   {result.reason}")