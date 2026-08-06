from __future__ import annotations

from datetime import date
from pathlib import Path

import yaml
from loguru import logger
from pydantic import BaseModel, field_validator

DEFAULT_IGNORE_FILENAME = ".dockerls-ignore.yaml"


class IgnoreRule(BaseModel):
    cve: str
    justification: str = ""
    expires: date | None = None

    @field_validator("cve")
    @classmethod
    def _upper_cve(cls, v: str) -> str:
        return v.strip().upper()

    @property
    def is_expired(self) -> bool:
        if self.expires is None:
            return False
        return date.today() > self.expires


def load_ignore_rules(path: Path | None = None) -> list[IgnoreRule]:
    """Load CVE ignore rules from a `.dockerls-ignore.yaml` file. Expired
    rules are dropped (a vulnerability whose exemption lapsed is no longer
    ignored). Missing or malformed files degrade to "no rules" rather than
    failing the scan."""
    target = path or Path.cwd() / DEFAULT_IGNORE_FILENAME
    if not target.exists():
        return []

    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        logger.warning(f"Could not parse {target}: {e}")
        return []

    entries = raw.get("ignores", []) if isinstance(raw, dict) else []
    rules: list[IgnoreRule] = []
    for entry in entries:
        try:
            rule = IgnoreRule.model_validate(entry)
        except Exception as e:
            logger.warning(f"Skipping invalid ignore rule {entry}: {e}")
            continue
        if rule.is_expired:
            logger.info(f"Ignore rule for {rule.cve} expired on {rule.expires}, no longer applied")
            continue
        rules.append(rule)
    return rules


def active_ignored_cve_ids(rules: list[IgnoreRule]) -> set[str]:
    return {r.cve for r in rules if not r.is_expired}
