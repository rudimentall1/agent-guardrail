# Guardrail

**A policy firewall for AI agent tool calls.**

Agents are increasingly allowed to run shell commands, call paid APIs, send
emails, move money, and delete data — autonomously. Guardrail sits between
an agent's *decision* to call a tool and the tool actually *running*, and
enforces a deterministic policy: allow it, warn and require confirmation,
or block it outright.

No LLM judgment involved in the decision itself. No risk score you have to
trust. A rule either matches your policy file or it doesn't, and every
decision says exactly which rule fired and why.

```
Agent proposes: wallet.transfer(amount=9999, to="0xabc")
                          |
                          v
                 Guardrail Engine
        (blocklist / patterns / caps / domains / rate limit)
                          |
                          v
   BLOCK — "amount=9999 exceeds cap 5 for wallet.transfer (unknown agent)"
```

---

## Why this, not another "AI risk scoring" tool

Most "AI agent security" projects (including an earlier project of mine)
lean on statistical risk scores computed from data nobody can actually
verify at build time — wallet age, "reputation," contract "risk" — which
either requires paid data feeds you don't have yet, or quietly becomes
mock data pretending to be real. That's fine for prototyping, dishonest to
ship.

Guardrail does the opposite: it only makes claims it can back up. Every
check is a deterministic rule — a blocklist entry, a regex match, a
numeric cap, a rate limit — evaluated against a policy file you write and
can audit yourself, backed by an actual persistent audit log (SQLite) you
can query. Nothing here pretends to know something it doesn't.

It's also **not blockchain-specific**. Any agent that calls tools —
shell execution, email, HTTP requests, file deletion, database writes,
crypto transactions, whatever — can be gated by the same engine.

---

## Two ways to use it — know the difference

### 1. MCP server (`mcp_server.py`) — the easy on-ramp, advisory only

Exposes `guardrail_check`, `guardrail_record_outcome`, and
`guardrail_agent_history` as MCP tools any MCP-compatible agent (Claude
Desktop, Claude Code, custom MCP clients) can call. Zero extra
infrastructure, works today.

**Be clear-eyed about its limit:** like any tool an LLM can choose to
call, nothing stops the model from just not calling it before acting. It
only helps if the calling agent is instructed to always check first.

### 2. `guardrail.decorator.enforce` — the real guarantee

Wraps the actual Python function that performs a tool's side effect. The
check runs in your code, before the wrapped function executes — the model
never gets a chance to call the real function directly, only the wrapped
one. This is what makes a `BLOCK` actually unbypassable, at the cost of
needing to integrate it into your own agent's tool-execution code (not
just drop in an MCP config).

```python
from guardrail.decorator import enforce, BlockedActionError

@enforce(engine, tool_name="send_email")
def send_email(agent_id: str, to: str, subject: str, body: str):
    ...  # only runs if the decision is ALLOW or WARN-and-confirmed
```

If you're building your own agent loop (LangChain, CrewAI, a custom MCP
host, a Slack bot with tool access), use the decorator. If you're wiring
an existing MCP-compatible client, start with the MCP server and add the
decorator later where it matters most.

---

## Quickstart

```bash
pip install -r requirements.txt
```

### CLI (no infra needed)

```bash
python3 cli.py check --agent trading-agent-001 --tool wallet.transfer \
  --args '{"amount": 9999, "to": "0xabc"}'
```

```json
{
  "decision": "BLOCK",
  "matched_rules": [
    {"rule": "numeric_cap_exceeded", "severity": "BLOCK",
     "message": "amount=9999.0 exceeds cap 5 for 'wallet.transfer' (unknown agent)"},
    {"rule": "confirmation_required", "severity": "WARN",
     "message": "Tool 'wallet.transfer' always requires human confirmation"}
  ],
  ...
}
```

### As an MCP server

Add to Claude Desktop / Claude Code's MCP config
(`claude_desktop_config.json` or equivalent):

```json
{
  "mcpServers": {
    "guardrail": {
      "command": "python3",
      "args": ["/absolute/path/to/agent-guardrail/mcp_server.py"],
      "env": {
        "GUARDRAIL_POLICY": "/absolute/path/to/agent-guardrail/policies/default.yaml"
      }
    }
  }
}
```

Then instruct your agent (in its system prompt) to always call
`guardrail_check` before any action that spends money, deletes data,
sends something externally, or runs code.

### As a decorator in your own agent code

See `examples/example_agent_usage.py` — run it directly:

```bash
python3 examples/example_agent_usage.py
```

---

## Writing a policy

Policies are plain YAML — see `policies/default.yaml` for a real, working
starting point with comments explaining each section. Five rule types:

| Rule type | What it checks |
|---|---|
| `blocked_tools` | Tool names that are never allowed |
| `confirmation_required_tools` | Tool names that always produce `WARN` |
| `argument_patterns` | Regex against the JSON-serialized call arguments (catches destructive shell commands, SQL, leaked credentials, path traversal, regardless of which tool carries them) |
| `numeric_caps` | Per-tool numeric field caps, tighter for agents with no history |
| `domain_rules` | Allow/deny lists on a URL or email-recipient field, per tool |
| `rate_limits` | Sliding-window call limits per (agent, tool), backed by SQLite |

No code changes needed to adjust any of this — edit the YAML, restart the
process (or the MCP server).

---

## Running the tests

The whole engine is stdlib-only except PyYAML for policy loading, so the
test suite runs with just that one dependency installed:

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

31 tests cover rule evaluation, the full engine pipeline (including real
SQLite-backed rate limiting and audit persistence), the `enforce`
decorator (including that a `BLOCK` genuinely prevents the wrapped
function from running), and the hand-rolled MCP server's JSON-RPC
handling — verified end-to-end over an actual stdio pipe, not just unit
tests against internal methods.

---

## What's honestly still missing

- **No built-in confirmation UI.** `on_warn` in the decorator, and the
  advisory nature of the MCP tools, are the integration points — you
  supply the actual human-in-the-loop mechanism (Slack prompt, CLI
  input, a ticket, whatever fits your system).
- **Single-process SQLite by default.** Fine for one agent process; for
  multiple replicas sharing rate limits/audit history, point every
  process at the same file on shared storage, or swap in a real
  database (the storage classes are small and easy to re-target).
- **No built-in secrets/PII redaction in the audit log.** Arguments are
  stored as-submitted. If your tools take sensitive arguments, redact
  before calling `evaluate()`, or extend `AuditLog` to redact specific
  fields before persisting.
- **The default policy is a reasonable starting point, not a complete
  threat model.** The included patterns catch well-known destructive
  shell/SQL patterns and obvious credential formats — extend
  `argument_patterns` for whatever your agents actually touch.

None of these are mocked or faked — they're just not built yet, and
they're the honest next steps if you adopt this.

---

## Project layout

```
guardrail/
    core/
        models.py     ActionRequest, RuleMatch, GuardrailDecision (stdlib only)
        policy.py       Policy loader (the one place PyYAML is used)
    rules.py           Deterministic rule evaluators
    storage/
        rate_limiter.py  SQLite-backed sliding-window rate limiter
        audit.py           SQLite-backed persistent audit log
    engine.py          GuardrailEngine — orchestrates rules + rate limit + audit
    decorator.py       enforce() — the unbypassable integration point
policies/
    default.yaml       Real, working default policy
mcp_server.py          Hand-rolled MCP stdio server (no external mcp SDK needed)
cli.py                 Manual check / history CLI
examples/
    example_agent_usage.py
tests/                 31 unit tests, all runnable with just PyYAML installed
```
