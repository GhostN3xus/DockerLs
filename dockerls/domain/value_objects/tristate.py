"""Three-valued logic for facts about an image.

A security fact has three states, not two: true, false, and *not
determined*. Collapsing the third into `False` is the single most dangerous
simplification available here, because every consumer downstream reads
`has_shell = False` as "this image has no shell" -- a hardening claim -- when
all that happened is that nobody looked.

The whole hardening and attack-surface analysis is therefore built on this
type rather than on `bool`, and an unknown never earns credit: a fact that
could not be determined contributes nothing to a score in either direction,
and is reported as `unknown` in the table and in `--format json`.
"""

from __future__ import annotations

from enum import StrEnum


class Tristate(StrEnum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"

    @classmethod
    def of(cls, value: bool | None) -> Tristate:
        """Lift an optional bool, mapping `None` to UNKNOWN.

        Use this at every boundary where a source may simply not answer --
        `dict.get()` on a registry payload, an absent catalogue key -- so the
        absence stays visible instead of becoming a false.
        """
        if value is None:
            return cls.UNKNOWN
        return cls.TRUE if value else cls.FALSE

    @property
    def is_known(self) -> bool:
        return self is not Tristate.UNKNOWN

    @property
    def is_true(self) -> bool:
        return self is Tristate.TRUE

    @property
    def is_false(self) -> bool:
        return self is Tristate.FALSE
