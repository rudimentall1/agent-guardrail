"""Tests against the real, shipped policies/default.yaml — not a synthetic
test policy. If someone edits default.yaml and breaks a pattern, these
tests are what catch it.
"""
import os
import unittest

from guardrail.core.models import ActionRequest, Decision
from guardrail.core.policy import Policy
from guardrail.engine import GuardrailEngine
from guardrail.storage.audit import AuditLog
from guardrail.storage.rate_limiter import RateLimiter

POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "policies", "default.yaml")


def new_engine() -> GuardrailEngine:
    policy = Policy.from_yaml_file(POLICY_PATH)
    return GuardrailEngine(policy=policy, audit_log=AuditLog(":memory:"), rate_limiter=RateLimiter(":memory:"))


class TestDefaultPolicyDestructivePatterns(unittest.TestCase):
    def setUp(self):
        self.engine = new_engine()

    def _blocked(self, tool_name: str, arguments: dict) -> bool:
        decision = self.engine.evaluate(ActionRequest(agent_id="test-agent", tool_name=tool_name, arguments=arguments))
        return decision.decision == Decision.BLOCK

    def test_root_recursive_chmod_is_blocked(self):
        self.assertTrue(self._blocked("execute_code", {"command": "chmod -R 777 /"}))

    def test_firewall_flush_is_blocked(self):
        self.assertTrue(self._blocked("execute_code", {"command": "iptables -F"}))

    def test_docker_socket_mount_is_blocked(self):
        self.assertTrue(self._blocked("execute_code", {"command": "docker run -v /var/run/docker.sock:/var/run/docker.sock x"}))

    def test_drop_database_is_blocked(self):
        self.assertTrue(self._blocked("execute_sql", {"query": "DROP DATABASE prod;"}))

    def test_cloud_metadata_ssrf_is_blocked(self):
        self.assertTrue(self._blocked("http.request", {"url": "http://169.254.169.254/latest/meta-data/"}))

    def test_force_push_to_main_is_blocked(self):
        self.assertTrue(self._blocked("execute_code", {"command": "git push origin main --force"}))

    def test_github_token_pattern_is_blocked(self):
        self.assertTrue(self._blocked("send_webhook", {"body": "token=ghp_" + "a" * 36}))

    def test_ordinary_read_only_command_is_allowed(self):
        self.assertFalse(self._blocked("execute_code", {"command": "ls -la /var/log"}))

    def test_ordinary_scoped_sql_is_not_blocked(self):
        # WARN (missing-WHERE heuristic doesn't fire on a scoped statement), not BLOCK.
        decision = self.engine.evaluate(ActionRequest(
            agent_id="test-agent", tool_name="execute_sql",
            arguments={"query": "UPDATE users SET active=1 WHERE id=42;"},
        ))
        self.assertNotEqual(decision.decision, Decision.BLOCK)

    def test_confirmation_required_tools_all_produce_at_least_warn(self):
        policy = Policy.from_yaml_file(POLICY_PATH)
        for tool_name in policy.confirmation_required_tools:
            engine = new_engine()
            decision = engine.evaluate(ActionRequest(agent_id="fresh-agent", tool_name=tool_name, arguments={}))
            self.assertIn(decision.decision, (Decision.WARN, Decision.BLOCK),
                          f"{tool_name} should never silently ALLOW")


if __name__ == "__main__":
    unittest.main()
