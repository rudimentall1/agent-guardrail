# Publishing Guardrail

This is what "make people actually able to find and use this" means in
practice, as of mid-2026. I can build the server; I can't create an
account on your behalf or push to your GitHub — the steps below are
yours to run.

## 0. Before anything else

- [ ] Push this repo to a public GitHub repository.
- [ ] Fill in a real author/contact in `LICENSE` and `README.md`.
- [ ] Tag a `v1.0.0` release once you're happy with it — directories and
      the official registry both expect versioned releases, not "main".
- [ ] Decide on a public package (see below) — the registries below are
      metadata-only; they point at an actual published artifact.

## 1. Publish the Python package (npm/PyPI — pick one path)

The official MCP Registry and most directories expect your server to be
independently installable, not just "clone this repo." Easiest path for a
Python project: publish to **PyPI**.

```bash
pip install build twine
python -m build
twine upload dist/*
```

Add a `pyproject.toml` if you don't have one yet (you don't currently —
this repo ships as a plain script, which is fine for `git clone` use but
blocks PyPI publishing; add one when you're ready for this step).

For PyPI-based registry recognition, add this line to your `README.md`
(can be inside an HTML comment so it doesn't show up rendered):
```
mcp-name: io.github.<your-username>/guardrail
```

## 2. Publish to the official MCP Registry

This is the machine-readable registry that Claude Desktop, Cursor, and
other MCP clients query directly — the highest-leverage one.

```bash
# install the publisher CLI (macOS/Linux)
curl -L "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" | tar xz mcp-publisher
sudo mv mcp-publisher /usr/local/bin/

cd agent-guardrail
mcp-publisher init      # generates server.json from your repo — review it
mcp-publisher login github
mcp-publisher publish
```

Full walkthrough (worth reading before you run this, it explains what
`server.json` fields mean): https://modelcontextprotocol.io/registry/quickstart

## 3. Submit to the human-browsable directories

These are what people actually search when looking for "an agent
guardrail MCP server." Four matter in 2026:

| Directory | How to submit |
|---|---|
| **smithery.ai** | `smithery mcp publish <your-repo-url> -n <yourname>/guardrail`, or the web form at smithery.ai |
| **glama.ai/mcp** | Auto-indexes public GitHub repos with an MCP server; claim your listing via their docs once it's crawled |
| **mcp.so** | Click "Submit" on mcp.so, or open an issue/PR on their GitHub |
| **pulsemcp.com** | Click "Submit" in the top nav on pulsemcp.com — hand-reviewed, so write a clear one-paragraph description |

Also open a PR against the community-curated GitHub list:
**punkpeye/awesome-mcp-servers** — add Guardrail under the "Security" or
"Developer Tools" category, one line, matching their existing format.

There's a third-party CLI (`mcp-submit`) that pushes to 10+ directories
in one command if you don't want to do this by hand repeatedly for future
projects — search for it if you end up publishing more than one server.

## 4. What a good listing needs (same info, every directory)

Have this written down once, then paste it everywhere:

- **One-line description:** "A deterministic policy firewall for AI agent
  tool calls — blocks, warns, or allows based on rules you write, not a
  risk score."
- **Category:** Security / Developer Tools
- **Repository URL**
- **Install snippet** (the `mcpServers` JSON block from the README)
- **Tool count:** 3 (`guardrail_check`, `guardrail_record_outcome`,
  `guardrail_agent_history`)
- **Transport:** stdio
- **What makes it different, in one sentence:** "No mocked risk data, and
  the `enforce()` decorator makes blocks unbypassable, not just advisory."

## 5. After that — the parts that actually drive adoption

Submitting is the easy 10%. What actually gets something like this used:

- **Write one real integration guide** for a specific popular framework
  (LangChain tool wrapper, or a CrewAI callback) — generic READMEs don't
  convert, "here's exactly how to add this to your LangChain agent" does.
- **Post it once, somewhere with actual agent-builder traffic** — r/LocalLLaMA,
  Hacker News "Show HN", the MCP Discord/subreddit. One honest post
  explaining what it does and doesn't do (advisory MCP tool vs.
  unbypassable decorator) will land better than a sales pitch, given what
  this project already is.
- **Respond to issues fast for the first few weeks.** Early adopters
  filing an issue and getting silence is the #1 reason small tools die
  right after launch.
- **Keep `policies/default.yaml` growing based on real feedback** — if
  someone tells you their agent got past a rule, that's a real bug
  report, not a feature request; fix it the same day if you can.

None of this requires me — it requires you (or someone) actually doing
it. I've done the part I can: the tool is real, tested, and the
publishing mechanics above are accurate as of mid-2026.
