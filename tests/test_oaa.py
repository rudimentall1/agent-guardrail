import time
import unittest

import jwt

from guardrail.oaa import DEFAULT_TTL_SECONDS, InvalidOAAToken, generate_keypair, issue, verify


class TestOaaExpiry(unittest.TestCase):
    def setUp(self):
        self.private_pem, self.public_pem = generate_keypair()

    def _issue(self, **overrides):
        kwargs = dict(
            issuer="agent-guardrail-test",
            subject="agent-1",
            decision="ALLOW",
            action="tool_call:wallet.transfer",
            reason="risk within threshold",
            policy_ref="sha256:deadbeef",
            private_key_pem=self.private_pem,
        )
        kwargs.update(overrides)
        return issue(**kwargs)

    def test_token_has_exp_claim_by_default(self):
        token = self._issue()
        claims = jwt.decode(token, self.public_pem, algorithms=["EdDSA"])
        self.assertIn("exp", claims)
        self.assertEqual(claims["exp"], claims["iat"] + DEFAULT_TTL_SECONDS)

    def test_fresh_token_verifies(self):
        token = self._issue()
        result = verify(token, self.public_pem, expected_issuer="agent-guardrail-test")
        self.assertEqual(result.decision, "ALLOW")

    def test_expired_token_rejected(self):
        """Regression test for Finding 5 (same class as a fix earlier
        this session in the sibling Guardian project's guardian/oaa.py):
        tokens had no exp claim and were valid forever - a decision
        token attesting an action was ALLOWed at issuance could be
        replayed as 'proof of approval' indefinitely."""
        token = self._issue(ttl_seconds=-1)  # already expired at issuance
        with self.assertRaises(InvalidOAAToken):
            verify(token, self.public_pem)

    def test_explicit_none_ttl_omits_exp_claim(self):
        token = self._issue(ttl_seconds=None)
        claims = jwt.decode(token, self.public_pem, algorithms=["EdDSA"])
        self.assertNotIn("exp", claims)
        result = verify(token, self.public_pem)
        self.assertEqual(result.decision, "ALLOW")

    def test_custom_ttl_respected(self):
        token = self._issue(ttl_seconds=30)
        claims = jwt.decode(token, self.public_pem, algorithms=["EdDSA"])
        self.assertEqual(claims["exp"] - claims["iat"], 30)

    def test_invalid_decision_rejected_at_issuance(self):
        with self.assertRaises(InvalidOAAToken):
            self._issue(decision="MAYBE")

    def test_missing_required_claim_rejected_at_verification(self):
        # Build a token missing oaa_policy_ref directly via PyJWT,
        # bypassing issue()'s own validation, to exercise verify()'s
        # REQUIRED_CLAIMS check specifically.
        claims = {
            "iss": "x", "sub": "a", "iat": int(time.time()),
            "oaa_decision": "ALLOW", "oaa_action": "tool_call:x", "oaa_reason": "r",
        }
        token = jwt.encode(claims, self.private_pem, algorithm="EdDSA")
        with self.assertRaises(InvalidOAAToken):
            verify(token, self.public_pem)

    def test_wrong_issuer_rejected(self):
        token = self._issue(issuer="https://real-deployment.example")
        with self.assertRaises(InvalidOAAToken):
            verify(token, self.public_pem, expected_issuer="https://impostor.example")

    def test_tampered_token_fails_signature_check(self):
        token = self._issue()
        with self.assertRaises(jwt.InvalidSignatureError):
            verify(token[:-4] + "abcd", self.public_pem)


if __name__ == "__main__":
    unittest.main()
