"""Local web UI for human-in-the-loop confirmation of WARN decisions.

Runs a small HTTP server on localhost — stdlib only (`http.server`), no
Flask/FastAPI. Wire it in as the `on_warn` callback for
`guardrail.decorator.enforce`:

    confirmation = ConfirmationServer(port=8787)
    confirmation.start(open_browser=True)

    @enforce(engine, tool_name="wallet.transfer", on_warn=confirmation.request_confirmation)
    def transfer(...): ...

When a WARN decision needs a human, it appears at http://localhost:8787
with Approve / Reject buttons. The call to the wrapped function blocks
until someone responds, or until `timeout_seconds` elapses.

Fails CLOSED on timeout: if nobody responds in time, the action is
treated as rejected, not silently allowed. For a tool where "no answer in
time" should mean something else, wrap `request_confirmation` yourself.
"""
from __future__ import annotations

import json
import threading
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional

from guardrail.core.models import GuardrailDecision

PAGE_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guardrail — pending confirmations</title>
<style>
  :root { color-scheme: dark; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    max-width: 720px; margin: 40px auto; padding: 0 16px;
    background: #0b0f14; color: #e6edf3;
  }
  h1 { font-size: 18px; font-weight: 600; letter-spacing: -0.01em; }
  .sub { color: #8b949e; font-size: 13px; margin-top: -8px; margin-bottom: 24px; }
  .card {
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    padding: 16px 18px; margin-bottom: 12px;
  }
  .tool { font-weight: 600; font-size: 15px; }
  .agent { color: #8b949e; font-weight: 400; }
  .reason { color: #c9d1d9; font-size: 13px; margin: 10px 0; padding-left: 18px; }
  .reason li { margin-bottom: 4px; }
  .actions { margin-top: 10px; }
  button {
    padding: 8px 18px; border-radius: 6px; border: none; font-weight: 600;
    font-size: 13px; cursor: pointer; margin-right: 8px;
  }
  .approve { background: #238636; color: white; }
  .approve:hover { background: #2ea043; }
  .reject { background: #da3633; color: white; }
  .reject:hover { background: #f0463f; }
  .empty { color: #6e7681; font-size: 14px; padding: 32px 0; text-align: center; }
</style>
</head>
<body>
<h1>Guardrail</h1>
<div class="sub">Actions waiting on a human decision</div>
<div id="list" class="empty">Loading…</div>
<script>
async function refresh() {
  const res = await fetch('/api/pending');
  const items = await res.json();
  const list = document.getElementById('list');
  if (items.length === 0) {
    list.className = 'empty';
    list.innerHTML = 'Nothing pending.';
    return;
  }
  list.className = '';
  list.innerHTML = items.map(item => `
    <div class="card">
      <div class="tool">${escapeHtml(item.tool_name)} <span class="agent">— agent: ${escapeHtml(item.agent_id)}</span></div>
      <ul class="reason">${item.explanation.map(e => `<li>${escapeHtml(e)}</li>`).join('')}</ul>
      <div class="actions">
        <button class="approve" onclick="respond('${item.request_id}', true)">Approve</button>
        <button class="reject" onclick="respond('${item.request_id}', false)">Reject</button>
      </div>
    </div>
  `).join('');
}
function escapeHtml(s) {
  const d = document.createElement('div');
  d.innerText = s;
  return d.innerHTML;
}
async function respond(requestId, approved) {
  await fetch('/api/respond', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({request_id: requestId, approved: approved})
  });
  refresh();
}
refresh();
setInterval(refresh, 1500);
</script>
</body>
</html>"""


@dataclass
class _PendingItem:
    decision: GuardrailDecision
    event: threading.Event = field(default_factory=threading.Event)
    approved: bool = False


class ConfirmationServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8787, timeout_seconds: float = 300.0):
        self.host = host
        self.port = port
        self.timeout_seconds = timeout_seconds
        self._pending: Dict[str, _PendingItem] = {}
        self._lock = threading.Lock()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, open_browser: bool = False) -> None:
        handler_cls = self._make_handler()
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler_cls)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        if open_browser:
            webbrowser.open(f"http://{self.host}:{self.port}")

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()

    def request_confirmation(self, decision: GuardrailDecision) -> bool:
        """Use directly as the `on_warn` callback for `guardrail.decorator.enforce`.

        Blocks the calling thread until a human responds via the web UI, or
        until `timeout_seconds` elapses (fails CLOSED — treated as rejected).
        """
        item = _PendingItem(decision=decision)
        with self._lock:
            self._pending[decision.request_id] = item

        resolved = item.event.wait(self.timeout_seconds)

        with self._lock:
            self._pending.pop(decision.request_id, None)

        return item.approved if resolved else False

    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # silence default stderr request logging
                pass

            def do_GET(self):
                if self.path == "/":
                    self._send_html(200, PAGE_TEMPLATE)
                    return
                if self.path == "/api/pending":
                    with server._lock:
                        items = [
                            {
                                "request_id": rid,
                                "agent_id": item.decision.agent_id,
                                "tool_name": item.decision.tool_name,
                                "explanation": item.decision.explanation,
                            }
                            for rid, item in server._pending.items()
                        ]
                    self._send_json(200, items)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):
                if self.path == "/api/respond":
                    length = int(self.headers.get("Content-Length", 0))
                    try:
                        payload = json.loads(self.rfile.read(length) or b"{}")
                    except json.JSONDecodeError:
                        self._send_json(400, {"error": "invalid JSON"})
                        return

                    request_id = payload.get("request_id")
                    approved = bool(payload.get("approved"))

                    with server._lock:
                        item = server._pending.get(request_id)
                        if item is not None:
                            item.approved = approved
                            item.event.set()

                    self._send_json(200, {"ok": item is not None})
                    return
                self.send_response(404)
                self.end_headers()

            def _send_html(self, code: int, html: str) -> None:
                body = html.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _send_json(self, code: int, payload) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler
