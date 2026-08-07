"""A self-contained Dockerfile parser.

Deliberately not a third-party dependency: every security rule in
`dockerls.infrastructure.validators` needs line numbers, per-stage scoping,
and the `--flag` prefixes on RUN/COPY (that is where `--mount=type=secret`
and `--from` live). The available parsers drop at least one of those, and a
security tool that silently loses the flag it is looking for reports a clean
Dockerfile that is not clean.

The grammar handled here is the one Docker documents: an optional parser
directive block, comments, backslash line-continuations, heredocs, and
`FROM ... [AS name]` stage boundaries.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dockerls.domain.entities.dockerfile_analysis import (
    DockerfileInstruction,
    DockerfileStage,
    ParsedDockerfile,
)

if TYPE_CHECKING:
    from pathlib import Path

MAX_DOCKERFILE_BYTES = 2 * 1024 * 1024

_DIRECTIVE = re.compile(r"^#\s*(escape|syntax)\s*=\s*(\S+)\s*$", re.IGNORECASE)
_FLAG = re.compile(r"^--([A-Za-z][A-Za-z0-9-]*)(?:=(.*))?$")
_HEREDOC = re.compile(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?")
_ARG_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$")

KEYWORDS = frozenset(
    {
        "ADD",
        "ARG",
        "CMD",
        "COPY",
        "ENTRYPOINT",
        "ENV",
        "EXPOSE",
        "FROM",
        "HEALTHCHECK",
        "LABEL",
        "MAINTAINER",
        "ONBUILD",
        "RUN",
        "SHELL",
        "STOPSIGNAL",
        "USER",
        "VOLUME",
        "WORKDIR",
    }
)


class DockerfileParseError(ValueError):
    """The file could not be read or contains no instructions at all."""


def find_dockerfile(target: Path, explicit: Path | None = None) -> Path:
    """Resolve the Dockerfile for a build target.

    `target` may be the Dockerfile itself or a build-context directory.
    An explicit `--file` always wins, matching `docker build -f`.
    """
    if explicit is not None:
        if not explicit.is_file():
            raise DockerfileParseError(f"Dockerfile not found: {explicit}")
        return explicit
    if target.is_file():
        return target
    candidate = target / "Dockerfile"
    if candidate.is_file():
        return candidate
    raise DockerfileParseError(f"No Dockerfile found in {target}")


def parse_dockerfile(path: Path) -> ParsedDockerfile:
    """Read and parse `path`. Raises `DockerfileParseError` only when there
    is nothing to analyse -- a file with odd instructions still parses, and
    the oddities land in `parse_errors` for the report."""
    try:
        if path.stat().st_size > MAX_DOCKERFILE_BYTES:
            raise DockerfileParseError(
                f"{path} exceeds {MAX_DOCKERFILE_BYTES // 1024}KB; refusing to parse"
            )
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise DockerfileParseError(f"Could not read {path}: {e}") from e

    parsed = parse_dockerfile_text(text, path=str(path))
    if not parsed.instructions:
        raise DockerfileParseError(f"{path} contains no Dockerfile instructions")
    return parsed


def parse_dockerfile_text(text: str, path: str = "") -> ParsedDockerfile:
    lines = text.splitlines()
    escape_char = _escape_directive(lines)
    instructions: list[DockerfileInstruction] = []
    errors: list[str] = []

    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue

        start = index
        logical, index = _read_logical_line(lines, index, escape_char)
        keyword, _, remainder = logical.partition(" ")
        keyword = keyword.upper().strip()
        if keyword not in KEYWORDS:
            errors.append(f"Line {start + 1}: unrecognised instruction '{keyword[:20]}'")
            continue

        flags, value = _split_flags(remainder.strip())
        instructions.append(
            DockerfileInstruction(
                keyword=keyword,
                value=value,
                line=start + 1,
                end_line=index,
                flags=flags,
                raw="\n".join(lines[start:index]),
            )
        )

    parsed = ParsedDockerfile(
        path=path, instructions=instructions, lines=lines, parse_errors=errors
    )
    _assign_stages(parsed)
    return parsed


def _escape_directive(lines: list[str]) -> str:
    """Honour `# escape=\\`` -- Windows-style Dockerfiles use a backtick, and
    reading their continuations with a backslash merges unrelated lines."""
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            break
        match = _DIRECTIVE.match(stripped)
        if match and match.group(1).lower() == "escape":
            return match.group(2)[:1] or "\\"
    return "\\"


def _read_logical_line(lines: list[str], start: int, escape_char: str) -> tuple[str, int]:
    """Join one instruction's physical lines. Returns (text, next_index)."""
    parts: list[str] = []
    index = start
    heredoc_terminators: list[str] = []

    while index < len(lines):
        raw = lines[index]
        index += 1

        if heredoc_terminators:
            parts.append(raw)
            if raw.strip() == heredoc_terminators[0]:
                heredoc_terminators.pop(0)
            if not heredoc_terminators:
                break
            continue

        stripped = raw.strip()
        # A comment inside a continuation is not part of the command.
        if stripped.startswith("#") and parts:
            continue

        continues = stripped.endswith(escape_char)
        content = stripped[: -len(escape_char)].rstrip() if continues else stripped
        parts.append(content)

        heredoc_terminators.extend(_HEREDOC.findall(content))
        if heredoc_terminators:
            continue
        if not continues:
            break

    return " ".join(p for p in parts if p), index


def _split_flags(remainder: str) -> tuple[dict[str, str], str]:
    """Peel leading `--flag[=value]` tokens off an instruction's arguments.

    Only leading flags are consumed: `RUN --mount=... apt-get install -y
    --no-install-recommends x` must keep `--no-install-recommends` in the
    command text, because that is where the apt rule looks for it.
    """
    flags: dict[str, str] = {}
    tokens = remainder.split(" ")
    consumed = 0
    for token in tokens:
        if not token:
            consumed += 1
            continue
        match = _FLAG.match(token)
        if not match:
            break
        flags[match.group(1).lower()] = match.group(2) or ""
        consumed += 1
    return flags, " ".join(tokens[consumed:]).strip()


def _assign_stages(parsed: ParsedDockerfile) -> None:
    """Group instructions into stages and collect the global ARG scope.

    Global ARGs are resolved into the FROM lines as they are collected, so
    `FROM node:${NODE_VERSION}` is analysed as the tag it will actually
    become rather than as an unpinned reference.
    """
    stages: list[DockerfileStage] = []
    for instruction in parsed.instructions:
        if instruction.keyword == "ARG" and not stages:
            name, _, default = instruction.value.partition("=")
            match = _ARG_ASSIGN.match(name.strip())
            if match:
                parsed.global_args[match.group(1)] = default.strip().strip("\"'")
            continue

        if instruction.keyword == "FROM":
            resolved = parsed.resolve_args(instruction.value)
            base, name = _split_stage_name(resolved)
            stage = DockerfileStage(
                index=len(stages),
                base_image=base,
                name=name,
                platform=instruction.flags.get("platform", ""),
            )
            stages.append(stage)

        if stages:
            instruction.stage_index = len(stages) - 1
            stages[-1].instructions.append(instruction)

    parsed.stages = stages


def _split_stage_name(value: str) -> tuple[str, str]:
    tokens = value.split()
    if not tokens:
        return "", ""
    base = tokens[0]
    for i, token in enumerate(tokens):
        if token.upper() == "AS" and i + 1 < len(tokens):
            return base, tokens[i + 1]
    return base, ""
