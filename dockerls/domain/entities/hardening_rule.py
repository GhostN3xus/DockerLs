from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel

from dockerls.domain.entities.vulnerability import Severity


class Priority(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class HardeningRule(BaseModel):
    """A concrete, actionable improvement to a Dockerfile.

    Distinct from a `ValidationCheck`: a check states what the file does
    today, a rule states what to change and why it is worth changing. A
    suggestion never blocks a build.
    """

    rule_id: str
    title: str
    priority: Priority = Priority.MEDIUM
    # What the Dockerfile says now, and what to replace it with. Both are
    # plain text so a suggestion can be pasted straight into the file.
    current: str = ""
    suggested: str = ""
    reason: str = ""
    line: int = 0

    @classmethod
    def from_severity(cls, severity: Severity, **kwargs: object) -> HardeningRule:
        """Build a suggestion whose priority mirrors a rule's severity, so
        the two views of the same finding cannot drift apart."""
        mapping = {
            Severity.CRITICAL: Priority.HIGH,
            Severity.HIGH: Priority.HIGH,
            Severity.MEDIUM: Priority.MEDIUM,
            Severity.LOW: Priority.LOW,
            Severity.UNKNOWN: Priority.LOW,
        }
        return cls(priority=mapping.get(severity, Priority.MEDIUM), **kwargs)
