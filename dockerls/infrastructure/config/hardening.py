"""`.dockerls-hardening.yaml` -- per-repository build policy.

Separate from `Settings` on purpose. `Settings` is the user's machine-wide
preference; this file is the *project's* policy, lives in the repository,
and is reviewed like code. When both have an opinion the project file wins,
because that is the one a pull request can change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import yaml
from loguru import logger
from pydantic import BaseModel, Field, field_validator

from dockerls.domain.entities.build_validation import HardeningLevel

if TYPE_CHECKING:
    from pathlib import Path

DEFAULT_HARDENING_FILENAME = ".dockerls-hardening.yaml"

VALID_FAIL_ON = ("none", "critical", "high", "medium")
VALID_SBOM_FORMATS = ("cyclonedx", "spdx")
VALID_REPORT_FORMATS = ("json", "html", "sarif", "markdown", "md")


class HardeningConfigError(ValueError):
    """The policy file exists but cannot be honoured as written."""


class ValidationPolicy(BaseModel):
    hardening_level: HardeningLevel = HardeningLevel.STANDARD
    # Rules to skip entirely, by rule_id. A skipped rule is reported as
    # SKIP rather than silently dropped, so the report still shows that a
    # decision was made not to check it.
    skip_rules: list[str] = Field(default_factory=list)


class ScanningPolicy(BaseModel):
    enabled: bool = True
    fail_on: str = "critical"
    sbom: bool = True
    sbom_formats: list[str] = Field(default_factory=lambda: ["cyclonedx"])

    @field_validator("fail_on")
    @classmethod
    def _known_threshold(cls, v: str) -> str:
        value = v.strip().lower()
        if value not in VALID_FAIL_ON:
            raise ValueError(f"fail_on must be one of {', '.join(VALID_FAIL_ON)}")
        return value

    @field_validator("sbom_formats")
    @classmethod
    def _known_sbom_formats(cls, v: list[str]) -> list[str]:
        for fmt in v:
            if fmt.strip().lower() not in VALID_SBOM_FORMATS:
                raise ValueError(f"Unsupported SBOM format '{fmt}'")
        return [fmt.strip().lower() for fmt in v]


class ReportingPolicy(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["json"])
    output_dir: str = ".dockerls/reports"
    vault_push: bool = False
    vault_root: str = ""
    vault_path: str = ""

    @field_validator("formats")
    @classmethod
    def _known_formats(cls, v: list[str]) -> list[str]:
        for fmt in v:
            if fmt.strip().lower() not in VALID_REPORT_FORMATS:
                raise ValueError(f"Unsupported report format '{fmt}'")
        return [fmt.strip().lower() for fmt in v]


class BuildKitPolicy(BaseModel):
    enabled: bool = True
    inline_cache: bool = True


class ProjectPolicy(BaseModel):
    """One image in a `--batch` run."""

    name: str
    dockerfile: str = ""
    context: str = "."
    tag: str
    hardened_template: str = ""
    build_args: dict[str, str] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    push: bool = False


class HardeningConfig(BaseModel):
    validation: ValidationPolicy = Field(default_factory=ValidationPolicy)
    scanning: ScanningPolicy = Field(default_factory=ScanningPolicy)
    reporting: ReportingPolicy = Field(default_factory=ReportingPolicy)
    buildkit: BuildKitPolicy = Field(default_factory=BuildKitPolicy)
    projects: list[ProjectPolicy] = Field(default_factory=list)
    source_path: str = ""


def find_hardening_config(start: Path) -> Path | None:
    """Look for the policy file beside the build context, then upwards.

    Walking up matters for monorepos: the policy belongs to the repository,
    while `dockerls build` is usually run from a service subdirectory.
    """
    current = start.resolve() if start.is_dir() else start.resolve().parent
    for directory in (current, *current.parents):
        candidate = directory / DEFAULT_HARDENING_FILENAME
        if candidate.is_file():
            return candidate
    return None


def load_hardening_config(path: Path | None) -> HardeningConfig:
    """Parse the policy file. Unlike `.dockerls-ignore.yaml`, a malformed
    file here is fatal: silently ignoring a build policy would let a broken
    file turn a gated pipeline into an ungated one."""
    if path is None:
        return HardeningConfig()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise HardeningConfigError(f"Could not read {path}: {e}") from e
    if not isinstance(raw, dict):
        raise HardeningConfigError(f"{path} must contain a YAML mapping at the top level")

    # `build:` is accepted as an alias for the top level so the policy can be
    # written either flat or nested under a `build` key.
    body = raw.get("build") if isinstance(raw.get("build"), dict) else raw
    merged = {**{k: v for k, v in raw.items() if k != "build"}, **(body or {})}
    try:
        config = HardeningConfig.model_validate({**merged, "source_path": str(path)})
    except ValueError as e:
        raise HardeningConfigError(f"Invalid policy in {path}: {e}") from e
    logger.info(f"Loaded hardening policy from {path}")
    return config
