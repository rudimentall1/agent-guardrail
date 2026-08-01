"""Backwards-compatible entry point: `python3 cli.py ...`

The actual implementation lives in guardrail/__main__.py so it can also be
installed as the `guardrail` console command (see pyproject.toml). This
file just forwards to it for people running from a git clone without
installing the package.
"""
from guardrail.__main__ import main

if __name__ == "__main__":
    main()
