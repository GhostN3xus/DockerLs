"""What a threat-intelligence lookup actually established.

A lookup that returns nothing can mean four very different things, and this
codebase's central rule is that they must never be spent alike:

* the source **answered** and has no record (`ABSENT`) -- a finding, and one
  worth remembering for a while so it is not re-asked for every candidate;
* the source **could not be reached** (`NETWORK_ERROR`), told us to slow down
  (`RATE_LIMITED`), or sent something unusable (`INVALID_RESPONSE`) -- none of
  which says anything about the CVE, and none of which may be cached as if it
  did;
* the source was **not asked** (`UNAVAILABLE`: circuit open, disabled).

Only `FOUND` and `ABSENT` are answers. Everything else leaves the field
`UNKNOWN`, and "absent from OSV" never becomes "not exploitable".
"""

from __future__ import annotations

from enum import StrEnum


class IntelStatus(StrEnum):
    FOUND = "FOUND"
    ABSENT = "ABSENT"
    NETWORK_ERROR = "NETWORK_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    UNAVAILABLE = "UNAVAILABLE"

    @property
    def answered(self) -> bool:
        """True when the source itself said something about the record."""
        return self in (IntelStatus.FOUND, IntelStatus.ABSENT)
