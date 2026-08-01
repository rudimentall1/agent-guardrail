"""Tests the confirmation web server over real HTTP requests (urllib against
a live ThreadingHTTPServer on a free local port) — not mocked handler
methods. request_confirmation() genuinely blocks a background thread until
a POST to /api/respond arrives, exactly like it would in real use.
"""
import json
import threading
import time
import unittest
import urllib.request

from guardrail.confirmation.web_ui import ConfirmationServer
from guardrail.core.models import Decision, GuardrailDecision


def _fake_decision(request_id: str = "req-1") -> GuardrailDecision:
    return GuardrailDecision(
        decision=Decision.WARN, matched_rules=[], explanation=["needs a human"],
        agent_id="test-agent", tool_name="wallet.transfer", request_id=request_id,
    )


def _get(url: str):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def _post(url: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


class TestConfirmationServer(unittest.TestCase):
    def setUp(self):
        self.server = ConfirmationServer(port=0, timeout_seconds=5)
        # port=0 asks the OS for a free port; read back the real one.
        handler_cls = self.server._make_handler()
        from http.server import ThreadingHTTPServer
        self.server._httpd = ThreadingHTTPServer((self.server.host, 0), handler_cls)
        self.server.port = self.server._httpd.server_address[1]
        self.server._thread = threading.Thread(target=self.server._httpd.serve_forever, daemon=True)
        self.server._thread.start()
        self.base_url = f"http://{self.server.host}:{self.server.port}"

    def tearDown(self):
        self.server.stop()

    def test_root_page_serves_html(self):
        with urllib.request.urlopen(self.base_url + "/", timeout=5) as resp:
            body = resp.read().decode("utf-8")
        self.assertIn("Guardrail", body)

    def test_pending_is_empty_initially(self):
        self.assertEqual(_get(self.base_url + "/api/pending"), [])

    def test_approve_flow_unblocks_request_confirmation_with_true(self):
        decision = _fake_decision("req-approve")
        result_holder = {}

        def waiter():
            result_holder["approved"] = self.server.request_confirmation(decision)

        t = threading.Thread(target=waiter)
        t.start()

        # Wait until it actually shows up as pending before responding.
        for _ in range(50):
            if _get(self.base_url + "/api/pending"):
                break
            time.sleep(0.05)

        pending = _get(self.base_url + "/api/pending")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["request_id"], "req-approve")

        _post(self.base_url + "/api/respond", {"request_id": "req-approve", "approved": True})
        t.join(timeout=5)

        self.assertTrue(result_holder["approved"])
        self.assertEqual(_get(self.base_url + "/api/pending"), [])

    def test_reject_flow_unblocks_request_confirmation_with_false(self):
        decision = _fake_decision("req-reject")
        result_holder = {}

        def waiter():
            result_holder["approved"] = self.server.request_confirmation(decision)

        t = threading.Thread(target=waiter)
        t.start()
        for _ in range(50):
            if _get(self.base_url + "/api/pending"):
                break
            time.sleep(0.05)

        _post(self.base_url + "/api/respond", {"request_id": "req-reject", "approved": False})
        t.join(timeout=5)

        self.assertFalse(result_holder["approved"])

    def test_timeout_fails_closed(self):
        self.server.timeout_seconds = 0.2
        decision = _fake_decision("req-timeout")
        approved = self.server.request_confirmation(decision)
        self.assertFalse(approved)
        self.assertEqual(_get(self.base_url + "/api/pending"), [])


if __name__ == "__main__":
    unittest.main()
