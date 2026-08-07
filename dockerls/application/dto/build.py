from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from dockerls.domain.entities.build_validation import HardeningLevel, ValidationResult
from dockerls.domain.entities.hardening_rule import HardeningRule

if TYPE_CHECKING:
    from dockerls.domain.entities.scan_result import ScanResult


class BuildSecret(BaseModel):
    """A BuildKit secret mount.

    Modelled as an id plus a *source* (a file path or an environment
    variable name) and never as a value: the point of `--mount=type=secret`
    is that the material never becomes a build argument, so DockerLs must
    not be the component that turns it back into one.
    """

    secret_id: str
    # Exactly one of these is set.
    env: str = ""
    file: str = ""

    def to_cli_argument(self) -> str:
        if self.env:
            return f"id={self.secret_id},env={self.env}"
        return f"id={self.secret_id},src={self.file}"


class BuildOptions(BaseModel):
    """Everything the build engine needs for one image."""

    dockerfile_path: str
    context_path: str
    tag: str
    build_args: dict[str, str] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    secrets: list[BuildSecret] = Field(default_factory=list)
    no_cache: bool = False
    buildkit: bool = True
    inline_cache: bool = True
    platform: str = ""
    target: str = ""


class LayerInfo(BaseModel):
    digest: str = ""
    size_bytes: int = 0
    created_by: str = ""

    @property
    def size_human(self) -> str:
        return _human_size(self.size_bytes)


class BuildResult(BaseModel):
    """What the engine did. A failed build is still a result, not an
    exception, so its validation findings can be reported alongside."""

    success: bool
    tag: str = ""
    image_id: str = ""
    size_bytes: int = 0
    layers: list[LayerInfo] = Field(default_factory=list)
    duration_seconds: float = 0.0
    error: str = ""
    # Last lines of the engine's output, kept for the failure message. The
    # full log always goes to the log file.
    log_tail: str = ""
    buildkit_used: bool = True

    @property
    def size_human(self) -> str:
        return _human_size(self.size_bytes)

    @property
    def layer_count(self) -> int:
        return len(self.layers)


class ScannerSummary(BaseModel):
    """One scanner's counts, so a report can show two tools side by side
    rather than a single blended number that hides their disagreement."""

    scanner: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0
    fixable: int = 0
    status: str = "OK"
    evidence_path: str = ""

    @classmethod
    def from_scan(cls, scan: ScanResult) -> ScannerSummary:
        return cls(
            scanner=scan.scanner,
            critical=scan.critical_count,
            high=scan.high_count,
            medium=scan.medium_count,
            low=scan.low_count,
            total=scan.total_count,
            fixable=scan.fixable_count,
            status=scan.status.value,
            evidence_path=scan.evidence_path,
        )


class SbomInfo(BaseModel):
    fmt: str = "cyclonedx"
    file: str = ""
    components_count: int = 0


class BuildMetadata(BaseModel):
    timestamp: str = ""
    git_sha: str = ""
    git_branch: str = ""
    built_by: str = ""
    docker_version: str = ""
    buildkit: bool = True
    dockerls_version: str = ""


class FailingVulnerability(BaseModel):
    """A vulnerability at or above the `--fail-on` threshold, listed so a
    red CI run names what it tripped on instead of only its count."""

    cve: str
    severity: str
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    fixable: bool = False


class BuildReport(BaseModel):
    """The complete record of one `dockerls build` run.

    Serialised verbatim by `--ci-mode` and `--report report.json`, so its
    field names are a public interface -- CI pipelines parse them.
    """

    build_id: str
    image: str = ""
    dockerfile_path: str = ""
    context_path: str = ""
    status: str = "OK"
    reason: str = ""

    validation: ValidationResult
    build: BuildResult | None = None
    scans: list[ScannerSummary] = Field(default_factory=list)

    dockerfile_score: float = 0.0
    scan_score: float | None = None
    security_score: float = 0.0
    security_tier: str = "C"
    production_ready: bool = False
    tier_advice: str = ""

    recommendations: list[HardeningRule] = Field(default_factory=list)
    failing_vulnerabilities: list[FailingVulnerability] = Field(default_factory=list)
    sbom: SbomInfo | None = None
    build_metadata: BuildMetadata = Field(default_factory=BuildMetadata)
    report_file: str = ""
    log_file: str = ""

    @property
    def validation_passed(self) -> int:
        return len(self.validation.passed)

    @property
    def validation_warnings(self) -> int:
        return len(self.validation.warnings)

    @property
    def validation_errors(self) -> int:
        return len(self.validation.failures)


class BuildImageRequest(BaseModel):
    """One CLI invocation, normalised. The use case reads only this."""

    context_path: str
    dockerfile_path: str = ""
    tag: str = ""
    build_args: dict[str, str] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    secrets: list[BuildSecret] = Field(default_factory=list)
    hardening_level: HardeningLevel = HardeningLevel.STANDARD

    validate_only: bool = False
    suggest_only: bool = False
    force: bool = False

    scan: bool = True
    generate_sbom: bool = True
    fail_on: str = "none"

    no_cache: bool = False
    buildkit: bool = True
    platform: str = ""
    target: str = ""
    push: bool = False

    report_path: str = ""
    report_formats: list[str] = Field(default_factory=list)
    vault_push: bool = False
    vault_path: str = ""


class BuildImageResponse(BaseModel):
    """The use case's verdict. `exit_code` is the domain's decision, not the
    CLI's, so `--ci-mode` and the human output can never disagree about
    whether a build passed."""

    success: bool
    report: BuildReport
    exit_code: int = 0
    pushed: bool = False
    push_message: str = ""
    written_reports: list[str] = Field(default_factory=list)
    vault_note: str = ""


_UNITS = ("B", "KB", "MB", "GB", "TB")


def _human_size(size_bytes: int) -> str:
    size = float(size_bytes)
    for unit in _UNITS:
        if size < 1024 or unit == _UNITS[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TB"
