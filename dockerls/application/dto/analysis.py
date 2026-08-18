from __future__ import annotations

from pydantic import BaseModel, Field

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.image_facts import HardeningFacts
from dockerls.domain.entities.recommendation import Recommendation
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Vulnerability
from dockerls.domain.value_objects.confidence import Confidence


class DimensionReport(BaseModel):
    """A derived score plus everything needed to defend it.

    Both the hardening and attack-surface models are computed over the
    facts that could be determined, so the number alone is not enough: a
    reader needs the coverage it was computed at, and the named findings on
    either side. Carrying them together means the terminal, the JSON output
    and every exporter show the same defence of the same number.
    """

    score: float = 0.0
    #: Share of the model that could be determined, 0.0-1.0.
    coverage: float = 0.0
    #: False when coverage was too thin for the score to mean anything. The
    #: renderers show "n/a" rather than a confident-looking number.
    reportable: bool = False
    #: Determined properties that counted in the image's favour.
    positives: list[str] = Field(default_factory=list)
    #: Determined properties that counted against it.
    negatives: list[str] = Field(default_factory=list)
    #: Properties nothing could establish, named rather than omitted.
    undetermined: list[str] = Field(default_factory=list)


class ImageAnalysis(BaseModel):
    image: DockerImage
    scan: ScanResult
    security_score: float
    tier: str
    remediation_score: int
    # The domain's verdict, carried so the CLI and --format json state
    # it rather than each re-deriving the rule from the tier letter.
    production_ready: bool = True
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

    # --- Multi-dimensional assessment ------------------------------------
    # The evidence record every derived dimension below is computed from,
    # carried so a consumer can recompute them or apply its own policy.
    facts: HardeningFacts = Field(default_factory=HardeningFacts)
    # How well the image is configured, independently of its CVE counts.
    hardening: DimensionReport = Field(default_factory=DimensionReport)
    # How much an attacker inherits inside the container. Higher is *worse*.
    attack_surface: DimensionReport = Field(default_factory=DimensionReport)
    # How much the evidence behind all of the above is worth. Defaults to
    # UNVERIFIED so an analysis that skipped assessment can never read as
    # trustworthy by omission.
    confidence: Confidence = Confidence.UNVERIFIED
    confidence_reasons: list[str] = Field(default_factory=list)
    # Plain-language reasons this image ranked where it did, so a
    # recommendation never reduces to an unexplained number.
    why: list[str] = Field(default_factory=list)
    # Costs and caveats of moving to this image, stated alongside the
    # reasons. A recommendation that lists only upsides is advertising.
    trade_offs: list[str] = Field(default_factory=list)

    @property
    def pinned_reference(self) -> str:
        """What to actually deploy: digest-pinned when one was resolved."""
        return self.image.pinned_reference


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
    # Causa classificada (DB_INIT_FAILED, TIMEOUT, NOT_FOUND, ...). O terminal
    # mostra isto; `reason` guarda o stderr completo para log e --format json.
    kind: str = "UNKNOWN"


class RunMetrics(BaseModel):
    """What the run actually did, as opposed to what it found.

    The pipeline already knew every one of these numbers and discarded all
    of them, so "why did that take four minutes" and "is the cache working"
    were unanswerable from the outside. They are the difference between
    tags *discovered* and scans *performed*, which the digest deduplication
    and the cache can make very different.

    Carried on the result rather than printed, so `--format json` and the
    terminal report the same figures.
    """

    tags_discovered: int = 0
    # Tags left after collapsing those that share a manifest digest. The gap
    # between this and `tags_discovered` is what deduplication saved.
    unique_digests: int = 0
    cache_hits: int = 0
    # Scanner invocations actually made, excluding cache hits and duplicates.
    scans_performed: int = 0
    cross_validations: int = 0
    workers: int = 0
    # Tags that arrived without a digest and were pinned to one. Each is a
    # registry HEAD that buys deduplication across every source.
    digests_resolved: int = 0
    # Candidates whose OCI config was fetched and verified, which is what
    # makes their hardening facts measurements rather than claims.
    images_inspected: int = 0

    @property
    def duplicates_collapsed(self) -> int:
        return max(0, self.tags_discovered - self.unique_digests)

    @property
    def cache_hit_rate(self) -> float:
        """Share of candidates answered from cache, 0.0-1.0."""
        considered = self.cache_hits + self.scans_performed
        return self.cache_hits / considered if considered else 0.0


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
    metrics: RunMetrics = Field(default_factory=RunMetrics)

    @property
    def unverified_count(self) -> int:
        return len(self.unverified)


class ComparisonResult(BaseModel):
    images: list[ImageAnalysis]
    winner: str = ""
    summary: str = ""
    common_vulns: list[Vulnerability] = []
    unique_vulns: dict[str, list[Vulnerability]] = {}
