from __future__ import annotations

from pydantic import BaseModel, Field

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.recommendation import Recommendation
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Vulnerability


class ImageAnalysis(BaseModel):
    image: DockerImage
    scan: ScanResult
    security_score: float
    tier: str
    remediation_score: int
    is_eol: bool = False
    is_lts: bool = False
    recommendation: Recommendation | None = None
    # Set when a second scanner disagreed materially with the primary one.
    # A non-empty value means the score must be presented as disputed.
    scan_divergence: str = ""
    # Docker Hub linkage. `hub_tag_verified` is deliberately tri-state:
    # True = confirmed present, False = confirmed absent, None = not checked
    # (image not on Docker Hub, or verification unavailable).
    hub_url: str = ""
    hub_tag_verified: bool | None = None
    # scanner name -> raw scan JSON path, backing the score shown above.
    evidence_paths: dict[str, str] = Field(default_factory=dict)


class BaselineCriteria(BaseModel):
    """The exact thresholds an image had to clear to count as a match.

    Carried on the result so "no image found matching baseline" can state
    what the baseline actually was instead of leaving the user to guess.
    """

    max_critical: int
    max_high: int
    max_medium: int

    def describe(self) -> str:
        return (
            f"{self.max_critical} Critical, "
            f"{self.max_high} High, "
            f"{self.max_medium} Medium (and not EOL)"
        )


class UnverifiedImage(BaseModel):
    """A tag that could not be scanned successfully.

    These never carry a score or a tier -- an image with no proof of a
    successful scan is reported as unverified, not ranked.
    """

    image_reference: str
    status: str
    reason: str


class AnalysisResult(BaseModel):
    query: str
    total_tags_scanned: int
    baseline_met: bool
    recommendations: list[ImageAnalysis] = []
    alternatives: list[ImageAnalysis] = []
    errors: list[str] = []
    # Run accounting, used to render the summary line above the table.
    total_tags_analyzed: int = 0
    unverified: list[UnverifiedImage] = []
    log_file: str = ""
    evidence_manifest: str = ""
    baseline: BaselineCriteria | None = None
    # Catalogues that returned at least one candidate for this query.
    sources_searched: list[str] = []

    @property
    def unverified_count(self) -> int:
        return len(self.unverified)


class ComparisonResult(BaseModel):
    images: list[ImageAnalysis]
    winner: str = ""
    summary: str = ""
    common_vulns: list[Vulnerability] = []
    unique_vulns: dict[str, list[Vulnerability]] = {}
