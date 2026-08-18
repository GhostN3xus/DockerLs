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
* **expansion size** -- anchors are legitimate in these definitions, so
  they are not banned; instead the document is *composed* into a node graph
  (where an alias is a shared reference, and therefore costs nothing) and
  the size it would expand to is computed over that graph before anything
  is constructed. A counting heuristic is not enough here and this is worth
  stating plainly: nine levels of nine-fold aliasing is only ~72 aliases --
  comfortably under any sane per-document count -- and expands to 387
  million nodes. What has to be bounded is the product, not the tally;
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

#: Nodes the document may expand to. Measured on the composed graph before
#: construction, so a bomb is refused in linear time instead of being
#: discovered when memory runs out. Real definitions compose a few thousand
#: nodes; this leaves two orders of magnitude of headroom.
MAX_EXPANDED_NODES = 1_000_000

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

    # Compose, measure, then construct -- in that order. Composition builds
    # a graph in which an alias is one edge rather than a copy, so it is
    # bounded by the document's own length; construction is what multiplies,
    # and it does not happen until the expansion has been shown to be safe.
    # SafeLoader is used throughout: it constructs only plain scalars, lists
    # and dicts, never arbitrary objects from `!!python/object` tags.
    loader = yaml.SafeLoader(text)
    try:
        try:
            node = loader.get_single_node()
        except yaml.YAMLError as e:
            raise UnsafeYAMLError(f"{origin}: malformed YAML ({e})") from e
        except RecursionError as e:
            raise UnsafeYAMLError(f"{origin}: document nesting exhausted the parser") from e

        if node is None:
            return None

        expanded = _expanded_size(node, {})
        if expanded > MAX_EXPANDED_NODES:
            raise UnsafeYAMLError(
                f"{origin}: document expands to at least {expanded} nodes, over the "
                f"{MAX_EXPANDED_NODES} limit (alias-expansion bomb)"
            )

        try:
            data = loader.construct_document(node)
        except yaml.YAMLError as e:
            raise UnsafeYAMLError(f"{origin}: malformed YAML ({e})") from e
        except RecursionError as e:
            raise UnsafeYAMLError(f"{origin}: document nesting exhausted the parser") from e
    finally:
        loader.dispose()

    depth = _depth(data)
    if depth > MAX_DEPTH:
        raise UnsafeYAMLError(f"{origin}: nesting depth {depth} exceeds the {MAX_DEPTH} limit")
    return data


def _expanded_size(node: yaml.Node, memo: dict[int, int]) -> int:
    """How many nodes `node` would become once every alias is expanded.

    The composed graph shares anchored nodes, so each one is measured once
    and memoised by identity; a node referenced nine times contributes its
    size nine times to its parent's total. That is exactly the quantity a
    YAML bomb maximises, and computing it costs one walk of the graph.

    Totals are clamped to the limit as they accumulate. Without the clamp
    the arithmetic itself becomes the denial of service: the classic bomb's
    true size is a 400-million-digit intermediate nobody needs to compute in
    order to know it is too big.
    """
    cached = memo.get(id(node))
    if cached is not None:
        return cached

    if isinstance(node, yaml.ScalarNode):
        memo[id(node)] = 1
        return 1

    total = 1
    children: list[yaml.Node] = []
    if isinstance(node, yaml.SequenceNode):
        children = list(node.value)
    elif isinstance(node, yaml.MappingNode):
        children = [child for pair in node.value for child in pair]

    for child in children:
        total += _expanded_size(child, memo)
        if total > MAX_EXPANDED_NODES:
            total = MAX_EXPANDED_NODES + 1
            break

    memo[id(node)] = total
    return total


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
