"""Backwards-compatible entry point: `python3 mcp_server.py`

The actual implementation lives in guardrail/mcp_server.py so it's
included when the package is installed (see pyproject.toml's
guardrail-mcp-server console script). This file just forwards to it for
people running from a git clone without installing the package.
"""
from guardrail.mcp_server import GuardrailMCPServer, main

if __name__ == "__main__":
    main()
