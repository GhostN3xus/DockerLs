from __future__ import annotations

import re

from pydantic import BaseModel, Field

# Instructions that start a new build stage. Everything after one belongs
# to that stage until the next FROM.
STAGE_KEYWORD = "FROM"

# Base images we treat as "minimal": either a distroless/scratch runtime or
# a vendor that ships a deliberately reduced package set.
MINIMAL_BASE_MARKERS = (
    "scratch",
    "alpine",
    "distroless",
    "chainguard",
    "cgr.dev",
    "wolfi",
    "busybox",
    "-slim",
)

_ARG_REFERENCE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[-+][^}]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
)


class DockerfileInstruction(BaseModel):
    """One logical Dockerfile instruction.

    "Logical" rather than "physical": a backslash-continued command and a
    heredoc body are folded into a single instruction, because every
    security rule below reasons about the whole command, not the fragment
    that happened to fit on one line.
    """

    keyword: str
    value: str = ""
    # 1-based line of the instruction's *first* physical line, so a finding
    # points at somewhere the user can actually put a fix.
    line: int = 0
    end_line: int = 0
    # Parsed `--flag=value` prefixes (COPY --from, RUN --mount, ...). The
    # flags are stripped out of `value`.
    flags: dict[str, str] = Field(default_factory=dict)
    stage_index: int = 0
    raw: str = ""

    @property
    def is_exec_form(self) -> bool:
        """Whether the argument is a JSON array (`["node", "app.js"]`).

        Only meaningful for ENTRYPOINT/CMD/RUN. The shell form wraps the
        process in `/bin/sh -c`, which swallows signals and adds a shell to
        the runtime image.
        """
        stripped = self.value.strip()
        return stripped.startswith("[") and stripped.endswith("]")


class DockerfileStage(BaseModel):
    """A single `FROM ... [AS name]` block."""

    index: int
    base_image: str
    name: str = ""
    platform: str = ""
    instructions: list[DockerfileInstruction] = Field(default_factory=list)

    @property
    def base_name(self) -> str:
        """Repository part of the base image, without tag or digest."""
        ref = self.base_image
        if "@" in ref:
            ref = ref.split("@", 1)[0]
        # A colon in the final path segment is a tag; a colon earlier is a
        # registry port ("registry.internal:5000/app").
        head, _, last = ref.rpartition("/")
        if ":" in last:
            last = last.split(":", 1)[0]
        return f"{head}/{last}" if head else last

    @property
    def base_tag(self) -> str:
        """Tag of the base image, or "" when none was written."""
        ref = self.base_image
        if "@" in ref:
            ref = ref.split("@", 1)[0]
        _, _, last = ref.rpartition("/")
        if ":" in last:
            return last.split(":", 1)[1]
        return ""

    @property
    def has_digest(self) -> bool:
        return "@sha256:" in self.base_image

    @property
    def is_scratch(self) -> bool:
        return self.base_image.strip().lower() == "scratch"

    @property
    def is_minimal_base(self) -> bool:
        ref = self.base_image.lower()
        return any(marker in ref for marker in MINIMAL_BASE_MARKERS)


class ParsedDockerfile(BaseModel):
    """The whole file, already resolved into stages and instructions."""

    path: str = ""
    stages: list[DockerfileStage] = Field(default_factory=list)
    instructions: list[DockerfileInstruction] = Field(default_factory=list)
    # ARG declarations that appear before the first FROM. Docker scopes
    # these globally and they are the only ones usable in a FROM line.
    global_args: dict[str, str] = Field(default_factory=dict)
    # Physical lines, kept so a report can quote the offending source.
    lines: list[str] = Field(default_factory=list)
    parse_errors: list[str] = Field(default_factory=list)

    @property
    def stage_count(self) -> int:
        return len(self.stages)

    @property
    def is_multi_stage(self) -> bool:
        return self.stage_count > 1

    @property
    def final_stage(self) -> DockerfileStage | None:
        return self.stages[-1] if self.stages else None

    @property
    def base_image(self) -> str:
        """The base image of the *final* stage -- the one that actually
        ships. In a multi-stage build the builder's base is irrelevant to
        the runtime attack surface."""
        final = self.final_stage
        return final.base_image if final else ""

    def instructions_of(self, *keywords: str) -> list[DockerfileInstruction]:
        wanted = {k.upper() for k in keywords}
        return [i for i in self.instructions if i.keyword in wanted]

    def final_stage_instructions(self, *keywords: str) -> list[DockerfileInstruction]:
        final = self.final_stage
        if final is None:
            return []
        wanted = {k.upper() for k in keywords}
        return [i for i in final.instructions if i.keyword in wanted]

    def resolve_args(self, text: str) -> str:
        """Substitute known ARG defaults into `$VAR` / `${VAR}` references.

        Without this, `FROM node:${NODE_VERSION}-alpine` reads as an
        unpinned tag to every rule that inspects the tag string, and the
        most carefully pinned Dockerfiles get the worst findings.
        """

        def replace(match: re.Match[str]) -> str:
            name = match.group(1) or match.group(2)
            return self.global_args.get(name, match.group(0))

        return _ARG_REFERENCE.sub(replace, text)
