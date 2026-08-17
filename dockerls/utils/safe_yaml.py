"""YAML parsing for documents fetched from the internet.

Every YAML this tool reads comes from somewhere it does not control -- the
Docker Hardened Images catalogue is fetched over HTTPS from GitHub, and a
proxy, a compromised mirror or a malicious fork can put anything in the
response body. `yaml.load` would be remote code execution outright; even
`yaml.safe_load` is only safe against *construction*, not against
resource exhaustion: a few hundred bytes of nested aliases expand into
gigabytes (the "billion laughs" / YAML bomb), and a deeply nested document
can exhaust the C stack during composition.

So parsing here is guarded on three axes before the loader ever runs:

* **size** -- the document is refused above a byte budget, so a hostile or
  misconfigured endpoint cannot stream an unbounded body into memory;
* **alias density** -- anchors are legitimate in these definitions but a
  document with a suspicious number of back-references is refused rather
  than expanded;
* **nesting depth** -- measured on the parsed result, and refused above a
  bound no legitimate image definition comes close to.

A refusal raises `UnsafeYAMLError`, which callers treat as "this definition
could not be read" -- never as "this definition is empty".
"""

from __future__ import annotations

from typing import Any

import yaml

#: 4 MiB. The largest definition in the DHI catalogue is under 100 KiB, so
#: this leaves two orders of magnitude of headroom while still bounding the
#: memory a single hostile response can cost.
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024

#: Aliases (`*ref`) are how a YAML bomb multiplies. The catalogue's own
#: definitions use very few, so a cap this generous only ever fires on a
#: document built to expand.
MAX_ALIASES = 256

#: Composition depth of the parsed structure. Image definitions nest about
#: six levels; anything past this is a stack-exhaustion attempt.
MAX_DEPTH = 32


class UnsafeYAMLError(ValueError):
    """A document was refused before or after parsing, on a safety bound."""


def safe_load_yaml(raw: str | bytes, *, origin: str = "<yaml>") -> Any:
    """Parse `raw` with `yaml.safe_load` behind explicit resource bounds.

    Returns whatever the document contained (usually a dict). Raises
    `UnsafeYAMLError` when a bound is exceeded or the document is malformed
    -- the caller decides what an unreadable definition means, and in this
    codebase it always means "unknown", never "clean".
    """
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw

    encoded_size = len(text.encode("utf-8", errors="replace"))
    if encoded_size > MAX_DOCUMENT_BYTES:
        raise UnsafeYAMLError(
            f"{origin}: document is {encoded_size} bytes, over the {MAX_DOCUMENT_BYTES} limit"
        )

    alias_count = _count_aliases(text)
    if alias_count > MAX_ALIASES:
        raise UnsafeYAMLError(
            f"{origin}: {alias_count} YAML aliases exceeds the {MAX_ALIASES} limit "
            "(possible alias-expansion bomb)"
        )

    try:
        # SafeLoader constructs only plain Python scalars, lists and dicts:
        # no arbitrary object instantiation, no `!!python/object` tags.
        data = yaml.load(text, Loader=yaml.SafeLoader)  # noqa: S506 - SafeLoader, not unsafe load
    except yaml.YAMLError as e:
        raise UnsafeYAMLError(f"{origin}: malformed YAML ({e})") from e
    except RecursionError as e:
        raise UnsafeYAMLError(f"{origin}: document nesting exhausted the parser") from e

    depth = _depth(data)
    if depth > MAX_DEPTH:
        raise UnsafeYAMLError(f"{origin}: nesting depth {depth} exceeds the {MAX_DEPTH} limit")
    return data


def _count_aliases(text: str) -> int:
    """Count `*alias` references without parsing.

    Deliberately done on the raw text: by the time the loader has resolved
    them the expansion has already happened, which is the cost being
    guarded against. Overcounting (a `*` inside a quoted string) only makes
    the guard stricter, and the bound is far above legitimate usage.
    """
    count = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        count += stripped.count(" *") + (1 if stripped.startswith("*") else 0)
    return count


def _depth(value: Any, level: int = 0) -> int:
    """Nesting depth of an already-parsed structure.

    Iterative rather than recursive on the hot path would be safer still,
    but the loader has already bounded what can reach here: `MAX_DEPTH` is
    checked against a structure `yaml.SafeLoader` managed to build, and the
    loader raises `RecursionError` (handled above) well before Python's own
    limit on anything deeper.
    """
    if level > MAX_DEPTH:
        return level
    if isinstance(value, dict):
        return max((_depth(v, level + 1) for v in value.values()), default=level)
    if isinstance(value, list | tuple):
        return max((_depth(v, level + 1) for v in value), default=level)
    return level
