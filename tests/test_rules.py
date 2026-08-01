import unittest

from guardrail.core.models import ActionRequest, Severity
from guardrail.core.policy import Policy
from guardrail.rules import (
    check_argument_patterns,
    check_blocked_tools,
    check_confirmation_required,
    check_domain_rules,
    check_numeric_caps,
)

SAMPLE_POLICY = Policy.from_dict({
    "blocked_tools": ["delete_database"],
    "confirmation_required_tools": ["send_email"],
    "argument_patterns": [
        {"name": "dangerous_rm", "pattern": r'rm\s+-rf\s+/(?=\s|"|$)', "severity": "BLOCK",
         "message": "destructive shell command"},
    ],
    "numeric_caps": {
        "wallet.transfer": {"field": "amount", "max_unknown_agent": 5, "max_known_agent": 1000},
    },
    "domain_rules": {
        "http.request": {"field": "url", "mode": "denylist", "domains": ["evil.example"]},
        "send_email": {"field": "recipient", "mode": "allowlist", "domains": ["trusted.example"]},
    },
})


class TestRules(unittest.TestCase):
    def test_blocked_tool_matches(self):
        req = ActionRequest(agent_id="a", tool_name="delete_database")
        matches = check_blocked_tools(req, SAMPLE_POLICY)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, Severity.BLOCK)

    def test_confirmation_required_matches(self):
        req = ActionRequest(agent_id="a", tool_name="send_email", arguments={"recipient": "x@trusted.example"})
        matches = check_confirmation_required(req, SAMPLE_POLICY)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, Severity.WARN)

    def test_argument_pattern_catches_destructive_command(self):
        req = ActionRequest(agent_id="a", tool_name="execute_code", arguments={"command": "rm -rf /"})
        matches = check_argument_patterns(req, SAMPLE_POLICY)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, Severity.BLOCK)

    def test_argument_pattern_ignores_safe_command(self):
        req = ActionRequest(agent_id="a", tool_name="execute_code", arguments={"command": "ls -la /tmp"})
        matches = check_argument_patterns(req, SAMPLE_POLICY)
        self.assertEqual(matches, [])

    def test_numeric_cap_blocks_unknown_agent_over_limit(self):
        req = ActionRequest(agent_id="a", tool_name="wallet.transfer", arguments={"amount": 100})
        matches = check_numeric_caps(req, SAMPLE_POLICY, is_known_agent=False)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, Severity.BLOCK)

    def test_numeric_cap_allows_known_agent_under_limit(self):
        req = ActionRequest(agent_id="a", tool_name="wallet.transfer", arguments={"amount": 100})
        matches = check_numeric_caps(req, SAMPLE_POLICY, is_known_agent=True)
        self.assertEqual(matches, [])

    def test_domain_denylist_blocks_listed_domain(self):
        req = ActionRequest(agent_id="a", tool_name="http.request", arguments={"url": "https://evil.example/x"})
        matches = check_domain_rules(req, SAMPLE_POLICY)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule, "domain_denied")

    def test_domain_denylist_allows_unlisted_domain(self):
        req = ActionRequest(agent_id="a", tool_name="http.request", arguments={"url": "https://safe.example/x"})
        matches = check_domain_rules(req, SAMPLE_POLICY)
        self.assertEqual(matches, [])

    def test_domain_allowlist_blocks_unlisted_recipient(self):
        req = ActionRequest(agent_id="a", tool_name="send_email", arguments={"recipient": "x@stranger.example"})
        matches = check_domain_rules(req, SAMPLE_POLICY)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule, "domain_not_allowed")

    def test_domain_allowlist_permits_listed_recipient(self):
        req = ActionRequest(agent_id="a", tool_name="send_email", arguments={"recipient": "x@trusted.example"})
        matches = check_domain_rules(req, SAMPLE_POLICY)
        self.assertEqual(matches, [])


if __name__ == "__main__":
    unittest.main()
