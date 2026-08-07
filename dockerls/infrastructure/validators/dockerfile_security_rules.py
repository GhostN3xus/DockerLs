"""The OWASP-derived rule set applied to a Dockerfile before it is built.

Each rule answers one question about the file and returns a verdict, a
human-readable reason and -- where one exists -- the line to fix. A rule
that cannot be evaluated returns SKIP rather than PASS: "we did not look"
must never render as "nothing wrong".

Rules only ever inspect the *final* stage when the finding is about the
shipped image (user, entrypoint, labels, base image). Builder stages are
discarded by Docker, so a finding there is noise -- and reporting it is how
a hardening tool trains its users to ignore it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from dockerls.domain.entities.build_validation import CheckStatus, ValidationCheck
from dockerls.domain.entities.vulnerability import Severity

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from dockerls.domain.entities.dockerfile_analysis import (
        DockerfileInstruction,
        ParsedDockerfile,
    )

# Environment variable names that carry a credential often enough that a
# literal value assigned to one is treated as a leak until proven otherwise.
SECRET_NAME_PATTERN = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|API[-_]?KEY|ACCESS[-_]?KEY|"
    r"PRIVATE[-_]?KEY|CREDENTIAL|AUTH[-_]?KEY|CLIENT[-_]?SECRET)",
    re.IGNORECASE,
)

# Files that must never be copied into an image: they are either
# credentials or the whole history of them.
SECRET_FILE_PATTERN = re.compile(
    r"(^|/)(\.env(\.[\w.-]+)?|\.npmrc|\.netrc|\.pypirc|id_rsa|id_ed25519|"
    r"\.git|\.aws|\.ssh|credentials|[\w.-]+\.pem|[\w.-]+\.key|[\w.-]+\.p12|"
    r"[\w.-]+\.pfx)$",
    re.IGNORECASE,
)

# Entries a .dockerignore must have before a `COPY . .` is safe.
REQUIRED_DOCKERIGNORE_ENTRIES = (".git", ".env")

PACKAGE_INSTALL_PATTERN = re.compile(
    r"\b(apt-get\s+install|apt\s+install|apk\s+add|yum\s+install|dnf\s+install|"
    r"pip\s+install|pip3\s+install|npm\s+(ci|install)|yarn\s+install)\b"
)

CACHE_CLEAN_PATTERN = re.compile(
    r"(rm\s+-rf?\s+[^\s&|;]*(/var/lib/apt/lists|/var/cache/apk|/var/cache/yum|"
    r"/root/\.cache|~/\.cache)|apt-get\s+clean|--no-cache\b|--no-cache-dir\b|"
    r"npm\s+cache\s+clean|yarn\s+cache\s+clean|dnf\s+clean\s+all|yum\s+clean\s+all)"
)

APT_INSTALL_PATTERN = re.compile(r"\bapt(-get)?\s+install\b")
SUDO_PATTERN = re.compile(r"(^|[\s;&|])sudo([\s;&|]|$)|\binstall\b[^;&|]*\bsudo\b")
SETUID_PATTERN = re.compile(r"chmod\s+[^\s;&|]*(?:[24][0-7]{3}|[ug]\+s)")
REMOTE_ADD_PATTERN = re.compile(r"^(https?://|git@|github\.com[:/])", re.IGNORECASE)

# Distroless publishes a dedicated non-root variant; using it is equivalent
# to a USER directive and must not be reported as running privileged.
NONROOT_BASE_PATTERN = re.compile(r"(:|-)nonroot\b", re.IGNORECASE)

ROOT_USERS = {"root", "0", "0:0", "root:root"}

MAINTAINER_LABELS = ("maintainer", "org.opencontainers.image.authors")
SECURITY_LABELS = (
    "security.scanner",
    "security.hardened",
    "security.cve-contact",
    "security.policy",
    "org.opencontainers.image.source",
)


@dataclass(frozen=True)
class RuleContext:
    """Everything a rule may look at: the parsed file and, when it exists
    on disk, the build context directory next to it."""

    dockerfile: ParsedDockerfile
    context_dir: Path | None = None


@dataclass(frozen=True)
class RuleOutcome:
    """A rule's raw answer, before it is turned into a `ValidationCheck`."""

    ok: bool
    message: str
    line: int = 0
    skipped: bool = False

    @staticmethod
    def passed(message: str, line: int = 0) -> RuleOutcome:
        return RuleOutcome(ok=True, message=message, line=line)

    @staticmethod
    def failed(message: str, line: int = 0) -> RuleOutcome:
        return RuleOutcome(ok=False, message=message, line=line)

    @staticmethod
    def skip(message: str) -> RuleOutcome:
        return RuleOutcome(ok=True, message=message, skipped=True)


@dataclass(frozen=True)
class SecurityRule:
    rule_id: str
    title: str
    severity: Severity
    fix: str
    evaluate: Callable[[RuleContext], RuleOutcome]

    def run(self, ctx: RuleContext) -> ValidationCheck:
        outcome = self.evaluate(ctx)
        if outcome.skipped:
            status = CheckStatus.SKIP
        elif outcome.ok:
            status = CheckStatus.PASS
        else:
            # CRITICAL and HIGH findings are errors -- they stop a standard
            # build. Everything else is a warning the user may accept.
            status = (
                CheckStatus.FAIL
                if self.severity in (Severity.CRITICAL, Severity.HIGH)
                else CheckStatus.WARN
            )
        return ValidationCheck(
            check=self.rule_id,
            title=self.title,
            status=status,
            severity=self.severity,
            message=outcome.message,
            line=outcome.line,
            fix="" if outcome.ok else self.fix,
        )


# --------------------------------------------------------------------------
# Rule implementations
# --------------------------------------------------------------------------


# A Dockerfile with no FROM has no shipped image to reason about, so every
# rule that inspects the final stage reports SKIP rather than inventing a
# verdict. Returned as a constant so the message cannot drift between rules.
NO_FINAL_STAGE = RuleOutcome(ok=True, message="No FROM instruction found", skipped=True)


def _check_base_image_pinned(ctx: RuleContext) -> RuleOutcome:
    if ctx.dockerfile.final_stage is None:
        return NO_FINAL_STAGE
    unpinned: list[tuple[str, int]] = []
    for stage in ctx.dockerfile.stages:
        if stage.is_scratch or stage.has_digest:
            continue
        # `FROM builder` referring to an earlier stage is not a registry
        # reference and has no tag to pin.
        if any(s.name and s.name == stage.base_image for s in ctx.dockerfile.stages):
            continue
        tag = stage.base_tag
        line = _stage_line(ctx.dockerfile, stage.index)
        if not tag:
            unpinned.append((f"{stage.base_image} (no tag: resolves to :latest)", line))
        elif tag.lower() == "latest":
            unpinned.append((f"{stage.base_image} (:latest is a moving target)", line))
    if unpinned:
        detail = "; ".join(item for item, _ in unpinned)
        return RuleOutcome.failed(f"Unpinned base image: {detail}", unpinned[0][1])
    return RuleOutcome.passed(f"Base image pinned: {ctx.dockerfile.base_image}")


def _check_non_root_user(ctx: RuleContext) -> RuleOutcome:
    final = ctx.dockerfile.final_stage
    if final is None:
        return NO_FINAL_STAGE

    users = ctx.dockerfile.final_stage_instructions("USER")
    if users:
        last = users[-1]
        name = ctx.dockerfile.resolve_args(last.value).strip()
        if name.lower() in ROOT_USERS:
            return RuleOutcome.failed(f"Final stage runs as root (USER {name})", last.line)
        return RuleOutcome.passed(f"Runs as non-root user: {name}", last.line)

    if NONROOT_BASE_PATTERN.search(final.base_image):
        return RuleOutcome.passed(
            f"Base image {final.base_image} already defaults to a non-root user"
        )
    return RuleOutcome.failed("No USER directive in the final stage; container will run as root")


def _check_secrets_not_in_env(ctx: RuleContext) -> RuleOutcome:
    findings: list[tuple[str, int]] = []
    for instruction in ctx.dockerfile.instructions_of("ENV", "ARG"):
        for name, value in parse_key_values(instruction.value):
            if not SECRET_NAME_PATTERN.search(name):
                continue
            if _is_placeholder(value):
                continue
            findings.append((f"{instruction.keyword} {name}", instruction.line))
    if findings:
        detail = ", ".join(item for item, _ in findings)
        return RuleOutcome.failed(
            f"Credential baked into an image layer: {detail} (visible forever in `docker history`)",
            findings[0][1],
        )
    return RuleOutcome.passed("No credentials assigned in ENV/ARG")


def _check_no_secret_files_copied(ctx: RuleContext) -> RuleOutcome:
    findings: list[tuple[str, int]] = []
    for instruction in ctx.dockerfile.instructions_of("COPY", "ADD"):
        # `COPY --from=builder` moves artefacts between stages, never host
        # files, so it cannot leak a developer's credentials.
        if instruction.flags.get("from"):
            continue
        for source in _copy_sources(instruction.value):
            if SECRET_FILE_PATTERN.search(source):
                findings.append((source, instruction.line))
    if findings:
        detail = ", ".join(item for item, _ in findings)
        return RuleOutcome.failed(
            f"Credential-bearing path copied into the image: {detail}", findings[0][1]
        )
    return RuleOutcome.passed("No credential files copied into the image")


def _check_dockerignore(ctx: RuleContext) -> RuleOutcome:
    if ctx.context_dir is None:
        return RuleOutcome.skip("No build context directory to inspect")
    wide_copies = [
        i
        for i in ctx.dockerfile.instructions_of("COPY", "ADD")
        if not i.flags.get("from") and _copies_whole_context(i.value)
    ]
    ignore_file = ctx.context_dir / ".dockerignore"
    if not ignore_file.is_file():
        if not wide_copies:
            return RuleOutcome.passed("No .dockerignore needed: nothing copies the whole context")
        return RuleOutcome.failed(
            "`COPY . .` with no .dockerignore: .git, .env and local caches "
            "will be baked into the image",
            wide_copies[0].line,
        )
    try:
        entries = {
            line.strip().lstrip("/").rstrip("/")
            for line in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
    except OSError as e:
        return RuleOutcome.skip(f"Could not read .dockerignore: {e}")

    missing = [
        entry
        for entry in REQUIRED_DOCKERIGNORE_ENTRIES
        if not any(e == entry or e.startswith(f"{entry}/") or e == f"{entry}*" for e in entries)
    ]
    if missing:
        return RuleOutcome.failed(f".dockerignore does not exclude: {', '.join(missing)}")
    return RuleOutcome.passed(f".dockerignore excludes {len(entries)} path(s) including .git/.env")


def _check_multi_stage(ctx: RuleContext) -> RuleOutcome:
    final = ctx.dockerfile.final_stage
    if final is None:
        return NO_FINAL_STAGE
    if ctx.dockerfile.is_multi_stage:
        return RuleOutcome.passed(f"Multi-stage build ({ctx.dockerfile.stage_count} stages)")
    if final.is_scratch:
        return RuleOutcome.passed("Single stage from scratch: nothing to strip out")
    return RuleOutcome.failed(
        "Single-stage build: compilers and build-time packages ship in the final image"
    )


def _check_package_cache_clean(ctx: RuleContext) -> RuleOutcome:
    if ctx.dockerfile.final_stage is None:
        return NO_FINAL_STAGE
    runs = ctx.dockerfile.final_stage_instructions("RUN")
    installs = [r for r in runs if PACKAGE_INSTALL_PATTERN.search(r.value)]
    if not installs:
        return RuleOutcome.skip("Final stage installs no packages")
    dirty = [r for r in installs if not CACHE_CLEAN_PATTERN.search(r.value)]
    # A later RUN in the same stage that only cleans is equally valid.
    if dirty and any(CACHE_CLEAN_PATTERN.search(r.value) for r in runs):
        dirty = [r for r in dirty if r.line > max(_clean_lines(runs), default=0)]
    if dirty:
        return RuleOutcome.failed(
            "Package manager cache kept in the image layer, inflating its size "
            "and its vulnerability surface",
            dirty[0].line,
        )
    return RuleOutcome.passed("Package manager cache cleaned in the same layer")


def _check_apt_no_install_recommends(ctx: RuleContext) -> RuleOutcome:
    offenders = [
        i
        for i in ctx.dockerfile.instructions_of("RUN")
        if APT_INSTALL_PATTERN.search(i.value) and "--no-install-recommends" not in i.value
    ]
    if not any(APT_INSTALL_PATTERN.search(i.value) for i in ctx.dockerfile.instructions_of("RUN")):
        return RuleOutcome.skip("No apt-get install in this Dockerfile")
    if offenders:
        return RuleOutcome.failed(
            "apt-get install without --no-install-recommends pulls in packages nobody audited",
            offenders[0].line,
        )
    return RuleOutcome.passed("apt-get install uses --no-install-recommends")


def _check_healthcheck(ctx: RuleContext) -> RuleOutcome:
    if ctx.dockerfile.final_stage is None:
        return NO_FINAL_STAGE
    checks = ctx.dockerfile.final_stage_instructions("HEALTHCHECK")
    live = [c for c in checks if c.value.strip().upper() != "NONE"]
    if live:
        return RuleOutcome.passed("HEALTHCHECK declared", live[-1].line)
    return RuleOutcome.failed(
        "No HEALTHCHECK: an unhealthy container cannot be detected or replaced"
    )


def _check_security_labels(ctx: RuleContext) -> RuleOutcome:
    if ctx.dockerfile.final_stage is None:
        return NO_FINAL_STAGE
    labels: dict[str, str] = {}
    for instruction in ctx.dockerfile.final_stage_instructions("LABEL", "MAINTAINER"):
        if instruction.keyword == "MAINTAINER":
            labels["maintainer"] = instruction.value
            continue
        labels.update({k.lower(): v for k, v in parse_key_values(instruction.value)})

    has_owner = any(key in labels for key in MAINTAINER_LABELS)
    has_security = any(key in labels for key in SECURITY_LABELS)
    if has_owner and has_security:
        return RuleOutcome.passed(
            f"{len(labels)} label(s) including ownership and security metadata"
        )
    missing = []
    if not has_owner:
        missing.append("an owner (maintainer / org.opencontainers.image.authors)")
    if not has_security:
        missing.append("security metadata (security.cve-contact / security.scanner)")
    return RuleOutcome.failed(
        f"Image cannot be attributed at incident time: missing {' and '.join(missing)}"
    )


def _check_minimal_base(ctx: RuleContext) -> RuleOutcome:
    final = ctx.dockerfile.final_stage
    if final is None:
        return NO_FINAL_STAGE
    if final.is_minimal_base or final.is_scratch:
        return RuleOutcome.passed(f"Minimal base image: {final.base_image}")
    return RuleOutcome.failed(
        f"{final.base_image} is a full distribution; a slim/alpine/distroless "
        "variant ships far fewer packages to patch",
        _stage_line(ctx.dockerfile, final.index),
    )


def _check_no_sudo(ctx: RuleContext) -> RuleOutcome:
    offenders = [i for i in ctx.dockerfile.instructions_of("RUN") if SUDO_PATTERN.search(i.value)]
    if offenders:
        return RuleOutcome.failed(
            "sudo installed or invoked: a container needing privilege escalation "
            "at runtime is a container running with too much privilege",
            offenders[0].line,
        )
    return RuleOutcome.passed("No sudo in the build")


def _check_no_setuid(ctx: RuleContext) -> RuleOutcome:
    offenders = [i for i in ctx.dockerfile.instructions_of("RUN") if SETUID_PATTERN.search(i.value)]
    if offenders:
        return RuleOutcome.failed(
            "SETUID/SETGID bit set on a binary: it will execute with the owner's "
            "privileges regardless of the container user",
            offenders[0].line,
        )
    return RuleOutcome.passed("No SETUID/SETGID bits set")


def _check_exec_form_entrypoint(ctx: RuleContext) -> RuleOutcome:
    if ctx.dockerfile.final_stage is None:
        return NO_FINAL_STAGE
    entries = ctx.dockerfile.final_stage_instructions("ENTRYPOINT", "CMD")
    if not entries:
        return RuleOutcome.failed("Neither ENTRYPOINT nor CMD in the final stage")
    shell_form = [e for e in entries if not e.is_exec_form]
    if shell_form:
        return RuleOutcome.failed(
            f"{shell_form[0].keyword} uses shell form: the process runs under "
            "/bin/sh -c and never receives SIGTERM",
            shell_form[0].line,
        )
    return RuleOutcome.passed("ENTRYPOINT/CMD use exec form")


def _check_no_remote_add(ctx: RuleContext) -> RuleOutcome:
    offenders: list[DockerfileInstruction] = []
    for instruction in ctx.dockerfile.instructions_of("ADD"):
        sources = _copy_sources(instruction.value)
        if any(REMOTE_ADD_PATTERN.match(s) for s in sources):
            offenders.append(instruction)
    if offenders:
        return RuleOutcome.failed(
            "ADD fetches a remote URL: the content is unverified and unpinned; "
            "use RUN with a checksum instead",
            offenders[0].line,
        )
    return RuleOutcome.passed("No remote fetches via ADD")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _stage_line(dockerfile: ParsedDockerfile, stage_index: int) -> int:
    for instruction in dockerfile.instructions:
        if instruction.keyword == "FROM" and instruction.stage_index == stage_index:
            return instruction.line
    return 0


def _clean_lines(runs: list[DockerfileInstruction]) -> list[int]:
    return [r.line for r in runs if CACHE_CLEAN_PATTERN.search(r.value)]


def parse_key_values(value: str) -> list[tuple[str, str]]:
    """Parse both ENV forms: `KEY=v KEY2=v2` and the legacy `KEY value`."""
    tokens = _split_respecting_quotes(value)
    if not tokens:
        return []
    if "=" not in tokens[0]:
        # Legacy form: everything after the first token is one value.
        return [(tokens[0], " ".join(tokens[1:]).strip("\"'"))]
    pairs: list[tuple[str, str]] = []
    for token in tokens:
        if "=" not in token:
            continue
        key, _, val = token.partition("=")
        pairs.append((key.strip(), val.strip().strip("\"'")))
    return pairs


def _split_respecting_quotes(value: str) -> list[str]:
    """Split on whitespace, but keep quoted values (which may contain
    spaces) attached to their key."""
    tokens: list[str] = []
    current: list[str] = []
    quote = ""
    for char in value:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            current.append(char)
            continue
        if char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


def _is_placeholder(value: str) -> bool:
    """Whether an assignment is a location or an indirection rather than a
    literal credential.

    `ENV API_KEY_FILE=/run/secrets/api_key` names where the secret will be
    mounted; `ENV API_KEY=$BUILD_KEY` defers to a build arg. Neither bakes
    anything into a layer, and flagging them trains users to ignore the rule.
    """
    stripped = value.strip()
    if not stripped:
        return True
    if stripped.startswith(("$", "/", "./", "~/")):
        return True
    return stripped.lower() in {"true", "false", "none", "null", "0", "1"}


def _copy_sources(value: str) -> list[str]:
    """The source operands of a COPY/ADD -- everything but the destination."""
    tokens = _split_respecting_quotes(value)
    if value.strip().startswith("["):
        # JSON form: ["src", "dest"]
        inner = value.strip().strip("[]")
        tokens = [t.strip().strip("\"',") for t in inner.split(",") if t.strip()]
    return [t.strip("\"'") for t in tokens[:-1]] if len(tokens) > 1 else []


def _copies_whole_context(value: str) -> bool:
    return any(source in (".", "./", "*") for source in _copy_sources(value))


SECURITY_RULES: tuple[SecurityRule, ...] = (
    SecurityRule(
        rule_id="secrets_not_in_env",
        title="No credentials in ENV/ARG",
        severity=Severity.CRITICAL,
        fix="Mount the secret at build time instead:\n"
        "  RUN --mount=type=secret,id=npm_token \\\n"
        "      NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci\n"
        "and pass it with `docker build --secret id=npm_token,env=NPM_TOKEN`.",
        evaluate=_check_secrets_not_in_env,
    ),
    SecurityRule(
        rule_id="no_secret_files_copied",
        title="No credential files in the image",
        severity=Severity.HIGH,
        fix="Add the path to .dockerignore and mount it with "
        "`RUN --mount=type=secret` if the build genuinely needs it.",
        evaluate=_check_no_secret_files_copied,
    ),
    SecurityRule(
        rule_id="non_root_user",
        title="Runs as a non-root user",
        severity=Severity.HIGH,
        fix="RUN addgroup -g 1000 appgroup && adduser -D -u 1000 -G appgroup appuser\nUSER appuser",
        evaluate=_check_non_root_user,
    ),
    SecurityRule(
        rule_id="base_image_pinned",
        title="Base image tag is pinned",
        severity=Severity.HIGH,
        fix="Pin an explicit version -- FROM node:22.11.0-alpine3.19 -- or a "
        "digest: FROM node@sha256:<digest>.",
        evaluate=_check_base_image_pinned,
    ),
    SecurityRule(
        rule_id="no_sudo",
        title="No sudo in the image",
        severity=Severity.HIGH,
        fix="Do everything needing privilege in the build (as root), then drop "
        "to an unprivileged USER for the runtime. Remove the sudo package.",
        evaluate=_check_no_sudo,
    ),
    SecurityRule(
        rule_id="no_setuid_binaries",
        title="No SETUID/SETGID bits",
        severity=Severity.HIGH,
        fix="Drop the setuid bit (chmod 0755) and grant the capability the "
        "process actually needs instead.",
        evaluate=_check_no_setuid,
    ),
    SecurityRule(
        rule_id="minimal_base",
        title="Minimal base image",
        severity=Severity.MEDIUM,
        fix="Switch to a reduced base: -alpine, -slim, gcr.io/distroless/*, or "
        "cgr.dev/chainguard/*.",
        evaluate=_check_minimal_base,
    ),
    SecurityRule(
        rule_id="multi_stage",
        title="Multi-stage build",
        severity=Severity.MEDIUM,
        fix="Compile in a builder stage and COPY --from=builder only the "
        "artefacts into a clean runtime stage.",
        evaluate=_check_multi_stage,
    ),
    SecurityRule(
        rule_id="package_cache_clean",
        title="Package cache cleaned",
        severity=Severity.MEDIUM,
        fix="Clean in the same RUN as the install:\n"
        "  RUN apk add --no-cache pkg\n"
        "  RUN apt-get update && apt-get install -y --no-install-recommends pkg \\\n"
        "      && rm -rf /var/lib/apt/lists/*",
        evaluate=_check_package_cache_clean,
    ),
    SecurityRule(
        rule_id="apt_no_install_recommends",
        title="apt-get install is restricted",
        severity=Severity.MEDIUM,
        fix="RUN apt-get install -y --no-install-recommends <package>",
        evaluate=_check_apt_no_install_recommends,
    ),
    SecurityRule(
        rule_id="exec_form_entrypoint",
        title="ENTRYPOINT/CMD use exec form",
        severity=Severity.MEDIUM,
        fix='ENTRYPOINT ["node"]\nCMD ["dist/index.js"]',
        evaluate=_check_exec_form_entrypoint,
    ),
    SecurityRule(
        rule_id="no_remote_add",
        title="No remote fetches via ADD",
        severity=Severity.MEDIUM,
        fix="RUN curl -fsSL <url> -o file && echo '<sha256>  file' | sha256sum -c -",
        evaluate=_check_no_remote_add,
    ),
    SecurityRule(
        rule_id="dockerignore_present",
        title=".dockerignore excludes sensitive paths",
        severity=Severity.MEDIUM,
        fix="Create a .dockerignore containing at least:\n.git\n.env\nnode_modules\n"
        "**/*.pem\n**/.aws",
        evaluate=_check_dockerignore,
    ),
    SecurityRule(
        rule_id="healthcheck",
        title="HEALTHCHECK declared",
        severity=Severity.LOW,
        fix="HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \\\n"
        '  CMD ["/app/healthcheck"]',
        evaluate=_check_healthcheck,
    ),
    SecurityRule(
        rule_id="security_labels",
        title="Ownership and security labels",
        severity=Severity.LOW,
        fix='LABEL maintainer="team@company.com"\n'
        'LABEL security.cve-contact="security@company.com"\n'
        'LABEL security.scanner="dockerls"',
        evaluate=_check_security_labels,
    ),
)

RULE_COUNT = len(SECURITY_RULES)
