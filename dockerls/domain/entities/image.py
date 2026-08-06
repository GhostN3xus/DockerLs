from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class DockerImage(BaseModel):
    name: str
    tag: str
    digest: str = ""
    size_bytes: int = 0
    architecture: str = "amd64"
    available_architectures: list[str] = Field(default_factory=list)
    os: str = "linux"
    last_updated: datetime | None = None
    pull_count: int = 0
    is_official: bool = False
    is_signed: bool = False
    full_reference: str = ""

    def model_post_init(self, __context: object) -> None:
        if not self.full_reference:
            self.full_reference = f"{self.name}:{self.tag}"

    @property
    def age_days(self) -> int:
        if not self.last_updated:
            return 365
        delta = datetime.now(tz=self.last_updated.tzinfo) - self.last_updated
        return max(0, delta.days)

    @property
    def is_alpine(self) -> bool:
        return "alpine" in self.tag.lower()

    @property
    def is_distroless(self) -> bool:
        return "distroless" in self.tag.lower() or "distroless" in self.name.lower()

    @property
    def is_slim(self) -> bool:
        return "slim" in self.tag.lower()

    @property
    def recently_updated(self) -> bool:
        return self.age_days <= 30
