"""Redacts likely secrets/PII from tool-call arguments before they're
written to the audit log.

The audit log's whole purpose is to persist exactly what an agent
attempted, verbatim, so a human can review it later. That's in direct
tension with not wanting raw API keys, passwords, or private keys sitting
in a queryable SQLite file forever. This module resolves that tension by
redacting only what it's confident about, and leaving everything else
untouched - a security tool that redacts too aggressively just pushes the
information loss problem from "readable" to "useless."

Two independent detection strategies, both conservative:

1. **Key-name matching** - if the argument's key looks like it holds a
   secret (``password``, ``api_key``, ``authorization``, ...), redact the
   value regardless of what it looks like. Cheap, predictable, and covers
   the overwhelming majority of real cases: tool arguments are usually
   named sensibly.
2. **Value-shape matching** - a couple of very high-confidence patterns
   (PEM private key blocks, JWT-shaped strings) are redacted even under an
   innocuous-looking key name, since the cost of missing one of these is
   high and the false-positive rate for these specific shapes is close to
   zero.

Deliberately NOT attempted: general-purpose "looks like a random secret"
entropy heuristics. Those have a much higher false-positive rate (a long
UUID or hash is not a secret) and would erode trust in the log being
otherwise faithful - consistent with this project's stance elsewhere
(intent_verification, decimals lookups, ...) that a wrong guess is worse
than an honest gap.
"""
from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

# Substring match against the (lowercased) argument key - deliberately
# substrings, not exact names, so `api_key`, `apiKey`, `x_api_key`,
# `stripe_api_key` etc. all match without maintaining an exhaustive list.
SENSITIVE_KEY_SUBSTRINGS = (
    "password", "passwd", "secret", "api_key", "apikey", "access_token",
    "auth_token", "authorization", "private_key", "privatekey",
    "credential", "ssn", "social_security", "credit_card", "card_number",
    "cvv", "cvc", "session_token", "refresh_token", "client_secret",
    "bearer",
)

_PEM_BLOCK_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
# Three base64url segments separated by dots is the JWT shape
# (header.payload.signature) - matching this specific shape has an
# extremely low false-positive rate for ordinary tool arguments.
_JWT_SHAPE_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


# Exact-match only (not substring, unlike SENSITIVE_KEY_SUBSTRINGS above)
# - these are common bare key names for a secret, but are also
# substrings of extremely common NON-secret parameter names, so they
# can't be added to the substring list without over-redacting. "token"
# is the case that matters most in practice: a plain OAuth/API token
# argument is very often just named "token" (Slack, Stripe, and many
# internal APIs all do this), but "token" is also a substring of
# max_tokens - one of the single most common LLM tool-call parameters
# in the whole agent-tooling ecosystem, and definitely not a secret.
EXACT_SENSITIVE_KEYS = frozenset({"token"})


def _key_looks_sensitive(key: str) -> bool:
    # Header-style keys use hyphens ("X-Api-Key"); normalize to underscores
    # so SENSITIVE_KEY_SUBSTRINGS doesn't need every separator variant
    # spelled out twice.
    normalized = key.lower().replace("-", "_")
    if normalized in EXACT_SENSITIVE_KEYS:
        return True
    return any(pattern in normalized for pattern in SENSITIVE_KEY_SUBSTRINGS)


def _value_looks_sensitive(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return bool(_PEM_BLOCK_RE.search(value)) or bool(_JWT_SHAPE_RE.match(value.strip()))


def redact_arguments(arguments: Any, extra_sensitive_keys: frozenset = frozenset()) -> Any:
    """Returns a redacted copy of `arguments`. Recurses into nested
    dicts/lists (tool arguments are frequently structured, e.g. a
    `headers` sub-object containing an `Authorization` field). Does not
    mutate the input."""
    if isinstance(arguments, dict):
        result = {}
        for key, value in arguments.items():
            if _key_looks_sensitive(key) or key.lower() in extra_sensitive_keys:
                result[key] = REDACTED
            elif _value_looks_sensitive(value):
                result[key] = REDACTED
            else:
                result[key] = redact_arguments(value, extra_sensitive_keys)
        return result
    if isinstance(arguments, list):
        return [redact_arguments(item, extra_sensitive_keys) for item in arguments]
    return arguments
