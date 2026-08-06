# Guardrail
<!-- mcp-name: io.github.rudimentall1/agent-guardrail -->

**A policy firewall for AI agent tool calls.**

Your agent wants to run a shell command, send an email, or move money.
Guardrail checks that request against rules you wrote, before it happens,
and either lets it through, asks a human, or blocks it — with a plain-
English reason every time.

## 60-second quickstart

```bash
git clone <this repo> && cd agent-guardrail
pip install -r requirements.txt

python3 cli.py check --agent trading-agent-001 --tool wallet.transfer \
  --args '{"amount": 9999, "to": "0xabc"}'
```

Or, once published, `pip install guardrail-mcp` gives you a `guardrail`
command directly — same output, no repo checkout required (falls back to
the policy bundled in the package if you don't point `--policy` at your
own file):

```bash
guardrail check --agent trading-agent-001 --tool wallet.transfer \
  --args '{"amount": 9999, "to": "0xabc"}'
```

```json
{
  "decision": "BLOCK",
  "matched_rules": [
    {"rule": "numeric_cap_exceeded", "severity": "BLOCK",
     "message": "amount=9999.0 exceeds cap 5 for 'wallet.transfer' (unknown agent)"}
  ]
}
```

That's it — no server, no account, no API key. `policies/default.yaml` is
the file that decided this; open it and change the numbers to match your
own rules.

---

## Why this, not another "AI risk scoring" tool

Most "AI agent security" projects (including an earlier project of mine)
lean on statistical risk scores computed from data nobody can actually
verify at build time — wallet age, "reputation," contract "risk" — which
either requires paid data feeds you don't have yet, or quietly becomes
mock data pretending to be real. Fine for prototyping, dishonest to ship.

Guardrail only makes claims it can back up. Every check is a deterministic
rule — a blocklist entry, a regex match, a numeric cap, a rate limit —
evaluated against a policy file you write and can audit yourself, backed
by a real, persistent audit log (SQLite) you can query. Nothing here
pretends to know something it doesn't.

It's also **not blockchain-specific**. Shell execution, email, HTTP
requests, file deletion, database writes, crypto transactions — same
engine, same policy file, same rules.

---

## Three ways to use it

### 1. CLI — for testing a policy by hand
Shown above. No setup, instant feedback while you write rules.

### 2. MCP server (`mcp_server.py`) — the easy on-ramp, advisory

Exposes `guardrail_check`, `guardrail_record_outcome`, and
`guardrail_agent_history` as MCP tools any MCP-compatible agent (Claude
Desktop, Claude Code, custom MCP clients) can call.

```json
{
  "mcpServers": {
    "guardrail": {
      "command": "python3",
      "args": ["/absolute/path/to/agent-guardrail/mcp_server.py"],
      "env": { "GUARDRAIL_POLICY": "/absolute/path/to/agent-guardrail/policies/default.yaml" }
    }
  }
}
```

Then tell your agent (in its system prompt) to always call
`guardrail_check` before spending money, deleting data, messaging someone
externally, or running code.

**Be clear-eyed about its limit:** like any MCP tool, nothing stops the
calling model from just not invoking it. This only helps if the agent is
instructed to always check first — for a guarantee it can't skip, see #3.

### 3. `guardrail.decorator.enforce` — the real guarantee

Wraps the actual Python function that performs a tool's side effect. The
check runs in your code, before that function executes — the model never
gets a chance to call the real function directly.

```python
from guardrail.decorator import enforce, BlockedActionError

@enforce(engine, tool_name="send_email")
def send_email(agent_id: str, to: str, subject: str, body: str):
    ...  # only runs if the decision is ALLOW, or WARN-and-confirmed
```

Use this if you're building your own agent loop (LangChain, CrewAI, a
custom MCP host, a Slack bot with tool access). Run `python3
examples/example_agent_usage.py` to see it block a real function call.

---

## Getting a human to actually confirm a WARN

`on_warn` is the hook — Guardrail ships two ready-made implementations:

**Local web UI** (`guardrail/confirmation/web_ui.py`) — a tiny built-in
server (stdlib only, no Flask) with Approve/Reject buttons. The wrapped
function blocks until someone clicks one, or times out (fails **closed** —
timeout means reject, not "allow by default").

```python
from guardrail.confirmation.web_ui import ConfirmationServer

confirmation = ConfirmationServer(port=8787, timeout_seconds=300)
confirmation.start(open_browser=True)

@enforce(engine, tool_name="wallet.transfer", on_warn=confirmation.request_confirmation)
def transfer(...): ...
```

Try it live: `python3 examples/example_web_confirmation.py`, then open
http://localhost:8787.

**Terminal prompt** (`guardrail/confirmation/cli_ui.py`) — for scripts and
local testing where a browser is overkill:

```python
from guardrail.confirmation.cli_ui import cli_confirm

@enforce(engine, tool_name="wallet.transfer", on_warn=cli_confirm)
def transfer(...): ...
```

Neither is required — `on_warn` is just a function `(decision) -> bool`,
so a Slack message, a ticket, or anything else you already use works too.

---

## Writing a policy

Policies are plain YAML — see `policies/default.yaml` for a real, working
starting point (11 confirmation-gated tools, 10 destructive-pattern
checks, numeric caps, domain rules, rate limits, all commented).

| Rule type | What it checks |
|---|---|
| `blocked_tools` | Tool names that are never allowed |
| `confirmation_required_tools` | Tool names that always produce `WARN` |
| `argument_patterns` | Regex against the JSON-serialized call arguments — destructive shell commands, SQL, leaked credentials, path traversal, SSRF, force-pushes, regardless of which tool carries them |
| `numeric_caps` | Per-tool numeric field caps, tighter for agents with no history |
| `domain_rules` | Allow/deny lists on a URL or email-recipient field, per tool |
| `rate_limits` | Sliding-window call limits per (agent, tool), backed by SQLite |

No code changes needed to adjust any of this — edit the YAML, restart the
process (or the MCP server).

---

## Running the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

46 tests: rule evaluation, the full engine pipeline (real SQLite-backed
rate limiting and audit persistence), the `enforce` decorator (proving a
`BLOCK` genuinely prevents the wrapped function from running), the
hand-rolled MCP server's JSON-RPC handling over an actual stdio pipe, the
confirmation web UI over real HTTP requests against a live server, and a
dedicated suite that checks the *shipped* `policies/default.yaml` — not
just synthetic test policies — actually catches what it claims to.

---

## What's honestly still missing

- **Single-process SQLite by default.** Fine for one agent process; for
  multiple replicas sharing rate limits/audit history, point every
  process at the same file on shared storage, or swap in a real database
  (the storage classes are small and easy to re-target).
- **No built-in secrets/PII redaction in the audit log.** Arguments are
  stored as-submitted. If your tools take sensitive arguments, redact
  before calling `evaluate()`, or extend `AuditLog` to redact specific
  fields before persisting.
- **The default policy is a reasonable starting point, not a complete
  threat model.** It catches well-known destructive shell/SQL patterns
  and obvious credential formats — extend `argument_patterns` for
  whatever your agents actually touch.
- **The confirmation web UI has no auth.** It binds to `127.0.0.1` by
  design (not exposed on the network), but anyone with local access to
  that port can approve/reject. Fine for a single developer's machine;
  put it behind your own auth if multiple people share the host.

None of these are mocked or faked — they're just not built yet, and
they're the honest next steps if you adopt this.

---

## Publishing this / getting people to actually use it

See `PUBLISHING.md` for a concrete checklist: MCP directories to submit
to, what a listing needs, and what "done" looks like.

---

## Project layout

```
guardrail/
    __main__.py            CLI implementation — also the `guardrail` console command
    mcp_server.py            MCP stdio server — also the `guardrail-mcp-server` console command
    core/
        models.py               ActionRequest, RuleMatch, GuardrailDecision (stdlib only)
        policy.py                 Policy loader (the one place PyYAML is used)
    rules.py                    Deterministic rule evaluators
    storage/
        rate_limiter.py           SQLite-backed sliding-window rate limiter
        audit.py                    SQLite-backed persistent audit log
    engine.py                    GuardrailEngine — orchestrates rules + rate limit + audit
    decorator.py                 enforce() — the unbypassable integration point
    confirmation/
        web_ui.py                    Local web UI for human approve/reject (stdlib http.server)
        cli_ui.py                      Terminal-prompt confirmation
    policies/default.yaml           Copy of the default policy bundled into the installed package
policies/default.yaml       Canonical, editable default policy (git-clone workflow)
cli.py                      Thin shim -> guardrail/__main__.py (for `python3 cli.py`)
mcp_server.py                Thin shim -> guardrail/mcp_server.py (for `python3 mcp_server.py`)
pyproject.toml               Package metadata — `pip install .` gives you `guardrail` + `guardrail-mcp-server`
.github/workflows/ci.yml      Runs the test suite + policy validation + package build on every push
examples/
    example_agent_usage.py       Decorator basics
    example_web_confirmation.py    Real browser-based approve/reject, live
tests/                       46 unit tests, all runnable with just PyYAML installed
CONTRIBUTING.md              How to add a rule type, ground rules
CHANGELOG.md                  Version history
PUBLISHING.md                 How to actually get this in front of people
landing/index.html             Static one-page site (open directly or host on GitHub Pages)
```
