"""Render third-party text as text, never as formatting instructions.

Rich interprets square-bracket markup in everything it prints, and a large
share of what this tool prints did not originate here. CVE titles come from
upstream advisories, package names and file paths come from inside the image
under analysis, error strings come from a scanner's stderr, and catalogue
metadata comes from a repository on the internet. All of it is data.

Left unescaped, a description reading

    [red]FIXED - no action needed[/red]

is *interpreted*: the brackets vanish, the words are styled, and the report
now contains a sentence that looks like the tool's own annotation. Whoever
controls an advisory or a package's metadata controls how a finding is
presented -- they can style a CRITICAL to look benign, or make text
disappear. That is the one place in this codebase where untrusted input
becomes presentation logic, and it closes here.

`safe()` is applied at the point of interpolation rather than by turning
markup off wholesale, because the styling this tool applies to its *own*
strings is what makes the output readable. The rule is simple: our literals
may carry markup; anything that arrived from outside goes through `safe`.
"""

from __future__ import annotations

from rich.markup import escape


def safe(value: object) -> str:
    """Escape Rich markup in `value` so it renders exactly as it reads.

    Accepts any object and stringifies it: the call sites interpolate CVE
    ids, package names, paths, counts and enum values, and requiring the
    caller to remember which of those are already strings is how one gets
    missed.
    """
    return escape("" if value is None else str(value))
