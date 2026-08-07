"""DockerLs held to its own rule set.

A hardening tool whose own artefacts fail its own checks is not making an
argument anyone has to take seriously. These run against the real repository
files, so they fail the moment one of them drifts.
"""

from pathlib import Path

import pytest

from dockerls.application.services.dockerfile_validator import OwaspDockerfileValidator
from dockerls.domain.entities.build_validation import HardeningLevel
from dockerls.infrastructure.config.hardening import load_hardening_config

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestOwnDockerfile:
    def test_it_exists_where_the_docs_say(self):
        assert (REPO_ROOT / "Dockerfile").is_file()

    def test_it_clears_every_rule(self):
        validator = OwaspDockerfileValidator()
        result = validator.validate(REPO_ROOT / "Dockerfile", REPO_ROOT)
        offenders = [(c.check, c.status.value, c.message) for c in result.checks if c.failed]
        assert offenders == [], f"DockerLs' own Dockerfile has findings: {offenders}"

    def test_it_clears_them_at_the_strictest_level_too(self):
        validator = OwaspDockerfileValidator(hardening_level=HardeningLevel.STRICT)
        assert not validator.validate(REPO_ROOT / "Dockerfile", REPO_ROOT).has_blocking_findings


class TestExamplePolicy:
    """The shipped example is documentation people copy, so a version of it
    the loader rejects is worse than no example."""

    PATH = REPO_ROOT / ".dockerls-hardening.yaml.example"

    def test_the_example_exists(self):
        assert self.PATH.is_file()

    def test_the_example_actually_loads(self):
        config = load_hardening_config(self.PATH)
        assert config.validation.hardening_level is HardeningLevel.STANDARD
        assert config.scanning.fail_on == "critical"

    @pytest.mark.parametrize(
        "section", ["validation:", "scanning:", "reporting:", "buildkit:", "projects:"]
    )
    def test_every_section_of_the_policy_is_demonstrated(self, section):
        assert section in self.PATH.read_text()
