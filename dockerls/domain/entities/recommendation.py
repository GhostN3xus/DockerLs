from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class ActionType(str, Enum):
    UPGRADE_IMAGE = "UPGRADE_IMAGE"
    SWITCH_TAG = "SWITCH_TAG"
    REBUILD_IMAGE = "REBUILD_IMAGE"
    UPDATE_PACKAGE = "UPDATE_PACKAGE"
    SWITCH_BASE = "SWITCH_BASE"
    WAIT_UPSTREAM = "WAIT_UPSTREAM"
    RESCAN = "RESCAN"


class RemediationStep(BaseModel):
    step_number: int
    action: ActionType
    description: str
    from_value: str = ""
    to_value: str = ""
    expected_impact: str = ""


class Recommendation(BaseModel):
    image_reference: str
    security_score: float
    tier: str
    remediation_score: int
    steps: list[RemediationStep] = []
    summary: str = ""
