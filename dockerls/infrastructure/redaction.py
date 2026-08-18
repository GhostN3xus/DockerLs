"""One redactor, used everywhere text leaves this process.

Credentials reach this tool through several doors: a registry token in a
`WWW-Authenticate` exchange, a Docker Hub PAT in an exception message, a
`user:password` embedded in a URL someone put in a config file, an
`Authorization` header echoed back by a scanner that failed. They then leave
through several more: the log file, the raw scan artifacts kept as evidence,
and anything a user attaches to a ticket.

Having the masking live inside the logging sink covered exactly one of those
doors. This module is the shared implementation; the log filter and the
evidence store both call it, so a pattern added here protects every path at
once.

Two rules shape the patterns:

* **Only the key and its separator survive.** `token=` stays so the line
  remains readable; no part of the value does.
* **Over-masking is the acceptable failure.** A redacted benign string costs
  a moment of confusion. A leaked token costs a credential rotation, and
  the leak is discovered later, by someone else.
"""

from __future__ import annotations

import re

#: What replaces a redacted value. Recognisable on sight, and distinct from
#: anything a real credential looks like. The exact string is part of the
#: observable contract -- it appears in every log file this tool has ever
#: written -- so it is carried over verbatim rather than modernised.
MASK = "***MASKED***"

# Key names that introduce a credential. Named for what it is -- a detection
# *pattern* -- so neither Bandit nor ruff has to be told to ignore a constant
# that merely looks like it holds a secret.
_SENSITIVE_KEY_PATTERN = (
    r"[\w.-]*(?:token|password|passwd|senha|secret|api[-_]?key|credential|auth)[\w.-]*"
)

# A quoted key/value pair, as it appears in JSON or a dict repr:
#   "token": "value"      'apiKey' : 'value'      "auth": {"token": "value"}
# The quote between the key and the separator is exactly what the previous
# pattern could not cross, which left every JSON-shaped log line in clear.
_QUOTED_KV = re.compile(
    rf"""(?P<prefix>["']?{_SENSITIVE_KEY_PATTERN}["']?\s*[:=]\s*)(?P<quote>["'])(?P<value>(?:\\.|[^"'\\])*)(?P=quote)""",
    re.IGNORECASE,
)

# An unquoted key/value pair: token=abc, senha: abc, x-api-key: abc.
_BARE_KV = re.compile(
    rf"(?P<prefix>\b{_SENSITIVE_KEY_PATTERN}\s*[=:]\s*)(?P<value>[^\s,;&\"'}}\]]+)", re.IGNORECASE
)

# Authorization schemes.
_SCHEME = re.compile(
    r"\b(?P<scheme>Bearer|Basic|Token|Digest)\s+(?P<value>[^\s,;\"'=:][^\s,;\"']*)",
    re.IGNORECASE,
)

# Credentials embedded in a URL: https://user:secret@host
_URL_USERINFO = re.compile(r"(?P<prefix>://[^/\s:@]+:)(?P<value>[^@/\s]+)(?P<at>@)")

# curl-style inline credentials: -u user:secret, --user user:secret
_CURL_USER = re.compile(r"(?P<prefix>(?:-u|--user)\s+[^\s:]+:)(?P<value>\S+)")

# Credential formats that are self-identifying, so they are redacted even
# when they appear with no key to introduce them -- a bare token inside a
# list or an exception message has no "token=" in front of it.
_KNOWN_SECRET_VALUE = re.compile(
    r"""
      \bdckr_pat_[A-Za-z0-9_-]{8,}                          # Docker Hub PAT
    | \bgh[pousr]_[A-Za-z0-9]{20,}                           # GitHub classic token
    | \bgithub_pat_[A-Za-z0-9_]{20,}                         # GitHub fine-grained PAT
    | \beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+  # JWT
    | \bAKIA[0-9A-Z]{16}\b                                   # AWS access key id
    | \bxox[baprs]-[A-Za-z0-9-]{10,}                          # Slack token
    """,
    re.VERBOSE,
)

# multipart/form-data, where the value sits on its own line after a blank
# line rather than next to the key.
_MULTIPART = re.compile(
    rf"""(?P<prefix>name=["']{_SENSITIVE_KEY_PATTERN}["'][^\n]*\r?\n\r?\n)(?P<value>[^\r\n]+)""",
    re.IGNORECASE,
)

_FILE_FORMAT = "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}"
_CONSOLE_FORMAT = (
    "<level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - {message}"
)


def redact(message: str) -> str:
    """Redact credentials from a log line in every shape they arrive in.

    Only the key name and separator (e.g. `token=`) are kept, never any part
    of the value. Over-masking a benign line is an acceptable cost; leaking
    a token into a log file is not, so the key patterns are deliberately
    broad.

    Order matters: scheme patterns run before the key/value ones, because
    in `auth: Bearer <token>` a key/value match would consume only the word
    `Bearer` and stop, leaving the credential in the clear.
    """
    result = _SCHEME.sub(lambda m: f"{m.group('scheme')} {MASK}", message)
    result = _URL_USERINFO.sub(lambda m: f"{m.group('prefix')}{MASK}{m.group('at')}", result)
    result = _CURL_USER.sub(lambda m: f"{m.group('prefix')}{MASK}", result)
    result = _MULTIPART.sub(lambda m: f"{m.group('prefix')}{MASK}", result)
    result = _QUOTED_KV.sub(
        lambda m: f"{m.group('prefix')}{m.group('quote')}{MASK}{m.group('quote')}", result
    )
    result = _BARE_KV.sub(lambda m: f"{m.group('prefix')}{MASK}", result)
    # Last: catch self-identifying credential formats that appeared with no
    # key in front of them for any of the patterns above to anchor on.
    result = _KNOWN_SECRET_VALUE.sub(MASK, result)
    return result
