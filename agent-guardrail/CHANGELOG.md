# Changelog

## 1.0.0

Initial release.

- Deterministic rule engine: blocked tools, confirmation-required tools,
  argument regex patterns, numeric caps, domain allow/deny lists,
  SQLite-backed sliding-window rate limits.
- `guardrail.decorator.enforce` — unbypassable enforcement by wrapping the
  real tool-execution function.
- Hand-rolled MCP stdio server (`guardrail-mcp-server` / `mcp_server.py`)
  exposing `guardrail_check`, `guardrail_record_outcome`,
  `guardrail_agent_history` — no external `mcp` SDK dependency.
- CLI (`guardrail` console command / `cli.py`): `check`, `history`,
  `policy validate`.
- Local human-confirmation web UI (`guardrail.confirmation.web_ui`, stdlib
  `http.server` only) and a terminal fallback
  (`guardrail.confirmation.cli_ui`).
- Persistent, queryable SQLite audit log.
- 10 destructive-pattern checks and 11 confirmation-gated tools in the
  bundled default policy — see `policies/default.yaml`.
- Installable via `pip install .` (console scripts: `guardrail`,
  `guardrail-mcp-server`); falls back to the policy bundled in the
  package when run outside a git clone.
- 46 tests, including a real stdio JSON-RPC round trip against the MCP
  server and real HTTP requests against the confirmation web UI.
