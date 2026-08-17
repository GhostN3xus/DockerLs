"""Parse one Docker Hardened Images definition file into declared metadata.

A definition is a YAML document describing how an image is built: which
packages go in, which account it runs as, which tags it publishes, when the
release goes end-of-life. The parsing here is deliberately total and
defensive -- every field is optional, every type is checked, and a document
that does not look like a definition yields `None` rather than a
half-populated object that later code would read as fact.

Nothing in this module decides anything about security. It converts a
vendor's claim into a typed claim; the verdict is made much further down,
after the tag has been resolved to a digest and scanned.
"""

from __future__ import annotations

from typing import Any

from dockerls.domain.entities.declared_metadata import (
    DEBUG_TOOL_PACKAGES,
    PACKAGE_MANAGER_PACKAGES,
    SHELL_PACKAGES,
    DeclaredImageMetadata,
)

DHI_CATALOG = "Docker Hardened Images"

#: Definitions list packages as `name`, `name=version`, or `!name` for an
#: explicit exclusion. An exclusion means the package is *removed* from the
#: base -- counting it as installed would invert its meaning.
_EXCLUSION_PREFIX = "!"

#: A definition that names more packages than this is either malformed or
#: hostile; the count is kept but the name matching stops, so a crafted
#: document cannot turn parsing into an O(n) walk of an unbounded list.
MAX_PACKAGES = 5000

#: Tags a definition may publish. DHI definitions list around a dozen
#: aliases per image; the cap bounds what a single document can inject into
#: the candidate list.
MAX_TAGS = 64


def parse_definition(data: Any, *, definition_url: str = "") -> DeclaredImageMetadata | None:
    """Convert a parsed definition document into `DeclaredImageMetadata`.

    Returns `None` when the document is not a mapping, or names neither an
    image nor any tag -- there is nothing to resolve against a registry, so
    there is no candidate.
    """
    if not isinstance(data, dict):
        return None

    tags = _string_tuple(data.get("tags"), limit=MAX_TAGS)
    image = _as_str(data.get("image"))
    if not image and not tags:
        return None

    packages = _package_names(data.get("contents"))
    os_release = _as_mapping(data.get("os-release"))
    dates = _as_mapping(data.get("dates"))
    accounts = _as_mapping(data.get("accounts"))

    return DeclaredImageMetadata(
        catalog=DHI_CATALOG,
        definition_url=definition_url,
        display_name=_as_str(data.get("name")),
        registry_repository=image,
        variant=_as_str(data.get("variant")),
        run_as_user=_as_str(accounts.get("run-as")),
        platforms=_string_tuple(data.get("platforms"), limit=32),
        release_date=_as_str(dates.get("release")),
        end_of_life=_as_str(dates.get("end-of-life")),
        os_id=_as_str(os_release.get("id")),
        os_version=_as_str(os_release.get("version-id")),
        declared_package_count=len(packages) if packages else None,
        entrypoint=_string_tuple(data.get("entrypoint"), limit=32),
        cmd=_string_tuple(data.get("cmd"), limit=32),
        tags=tags,
        shell_packages=_matching(packages, SHELL_PACKAGES),
        package_manager_packages=_matching(packages, PACKAGE_MANAGER_PACKAGES),
        debug_tool_packages=_matching(packages, DEBUG_TOOL_PACKAGES),
    )


def _package_names(contents: Any) -> list[str]:
    """Installed package names, with versions stripped and exclusions dropped.

    `nodejs-22=22.23.2-0` is the package `nodejs-22`; `!gawk` is gawk being
    *removed* from the base image and must not be counted as present.
    """
    if not isinstance(contents, dict):
        return []
    raw = contents.get("packages")
    if not isinstance(raw, list):
        return []

    names: list[str] = []
    for entry in raw[:MAX_PACKAGES]:
        if not isinstance(entry, str):
            continue
        name = entry.strip()
        if not name or name.startswith(_EXCLUSION_PREFIX):
            continue
        names.append(name.split("=", 1)[0].strip())
    return names


def _matching(packages: list[str], known: frozenset[str]) -> tuple[str, ...]:
    """Package names present in `known`, deduplicated and ordered.

    Matching is exact rather than substring: `libcurl4` is not `curl`, and
    treating it as one would report a fetch capability the image does not
    have. Debian's `-dev`/major-version suffixes are handled by listing the
    real package names in the sets themselves.
    """
    seen = {name for name in packages if name in known}
    return tuple(sorted(seen))


def _as_mapping(value: Any) -> dict[str, Any]:
    """A nested block, or an empty one when the key is absent or wrong-typed.

    Definitions are hand-written YAML: a block can be missing, be `null`
    (which parses to `None`, not `{}`), or be a list where a map is
    expected. All three must read as "not stated".
    """
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> str:
    """Coerce a scalar to a string, refusing structures.

    YAML happily produces ints, dates and nested maps where a string is
    expected (`version-id: 13` parses as an int). Anything that is not a
    scalar is dropped rather than stringified into `{'a': 1}`.
    """
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return ""


def _string_tuple(value: Any, *, limit: int) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    items = [_as_str(entry) for entry in value[:limit]]
    return tuple(item for item in items if item)
