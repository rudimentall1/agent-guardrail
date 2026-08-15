import json
import sqlite3
import unittest

from guardrail.core.models import ActionRequest, GuardrailDecision, Decision
from guardrail.storage.audit import AuditLog
from guardrail.storage.redaction import redact_arguments, REDACTED


def _decision(request_id="r1", agent_id="agent-1", tool_name="wallet.transfer") -> GuardrailDecision:
    return GuardrailDecision(
        request_id=request_id, agent_id=agent_id, tool_name=tool_name,
        decision=Decision.ALLOW, matched_rules=[], explanation=[],
    )


class TestRedactArguments(unittest.TestCase):
    def test_key_name_match_is_redacted(self):
        out = redact_arguments({"password": "hunter2", "amount": 5})
        self.assertEqual(out["password"], REDACTED)
        self.assertEqual(out["amount"], 5)

    def test_case_and_separator_insensitive_key_matching(self):
        out = redact_arguments({"API_Key": "x", "x-api-key": "y", "stripeApiKey": "z"})
        self.assertEqual(out["API_Key"], REDACTED)
        self.assertEqual(out["x-api-key"], REDACTED)
        self.assertEqual(out["stripeApiKey"], REDACTED)

    def test_ordinary_keys_are_left_untouched(self):
        out = redact_arguments({"amount": 100, "recipient": "0xabc", "note": "hello"})
        self.assertEqual(out, {"amount": 100, "recipient": "0xabc", "note": "hello"})

    def test_nested_dict_is_redacted(self):
        out = redact_arguments({"headers": {"Authorization": "Bearer abc123", "Content-Type": "json"}})
        self.assertEqual(out["headers"]["Authorization"], REDACTED)
        self.assertEqual(out["headers"]["Content-Type"], "json")

    def test_list_of_dicts_is_redacted(self):
        out = redact_arguments({"users": [{"password": "a"}, {"password": "b"}]})
        self.assertEqual(out["users"][0]["password"], REDACTED)
        self.assertEqual(out["users"][1]["password"], REDACTED)

    def test_pem_private_key_value_redacted_under_innocuous_key(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"
        out = redact_arguments({"config": pem})
        self.assertEqual(out["config"], REDACTED)

    def test_jwt_shaped_value_redacted_under_innocuous_key(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ"
        out = redact_arguments({"token_field_named_weird": jwt})
        self.assertEqual(out["token_field_named_weird"], REDACTED)

    def test_ordinary_uuid_is_not_redacted(self):
        # Guards against overly aggressive value-shape heuristics: a
        # random-looking UUID/hash under a normal key must survive.
        out = redact_arguments({"request_id": "550e8400-e29b-41d4-a716-446655440000"})
        self.assertEqual(out["request_id"], "550e8400-e29b-41d4-a716-446655440000")

    def test_extra_sensitive_keys_extends_default_list(self):
        out = redact_arguments({"internal_note": "sensitive"}, extra_sensitive_keys=frozenset({"internal_note"}))
        self.assertEqual(out["internal_note"], REDACTED)

    def test_does_not_mutate_input(self):
        original = {"password": "hunter2"}
        redact_arguments(original)
        self.assertEqual(original["password"], "hunter2")


class TestAuditLogRedactionIntegration(unittest.TestCase):
    def test_redaction_on_by_default(self):
        log = AuditLog(":memory:")
        request = ActionRequest(agent_id="agent-1", tool_name="http.call", arguments={"api_key": "sk-secret", "url": "https://x.com"})
        log.record_decision(request, _decision())

        row = log._conn.execute("SELECT arguments FROM decisions WHERE request_id='r1'").fetchone()
        stored = json.loads(row[0])
        self.assertEqual(stored["api_key"], REDACTED)
        self.assertEqual(stored["url"], "https://x.com")

    def test_redaction_can_be_disabled(self):
        log = AuditLog(":memory:", redact=False)
        request = ActionRequest(agent_id="agent-1", tool_name="http.call", arguments={"api_key": "sk-secret"})
        log.record_decision(request, _decision())

        row = log._conn.execute("SELECT arguments FROM decisions WHERE request_id='r1'").fetchone()
        stored = json.loads(row[0])
        self.assertEqual(stored["api_key"], "sk-secret")

    def test_extra_sensitive_keys_passed_through_from_constructor(self):
        log = AuditLog(":memory:", extra_sensitive_keys=frozenset({"customer_ssn"}))
        request = ActionRequest(agent_id="agent-1", tool_name="crm.update", arguments={"customer_ssn": "123-45-6789"})
        log.record_decision(request, _decision())

        row = log._conn.execute("SELECT arguments FROM decisions WHERE request_id='r1'").fetchone()
        stored = json.loads(row[0])
        self.assertEqual(stored["customer_ssn"], REDACTED)


if __name__ == "__main__":
    unittest.main()
