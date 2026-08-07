from __future__ import annotations

import asyncio
import json
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.application.dto.build import BuildImageRequest, BuildSecret
from dockerls.application.services.build_report_generator import EXIT_FAILED, EXIT_OK
from dockerls.application.use_cases.generate_hardened_dockerfile import (
    DEFAULT_OUTPUT_NAME,
    TemplateGenerationError,
)
from dockerls.cli.dependencies import (
    build_build_use_case,
    build_defaults,
    build_hardening_level,
    build_template_generator,
    enable_console_logging,
)
from dockerls.domain.entities.build_validation import CheckStatus, HardeningLevel
from dockerls.exporters.build_report_exporter import BuildReportExporterFactory
from dockerls.infrastructure.config.hardening import (
    HardeningConfig,
    HardeningConfigError,
    find_hardening_config,
    load_hardening_config,
)
from dockerls.infrastructure.templates.loader import TEMPLATES

if TYPE_CHECKING:
    from dockerls.application.dto.build import BuildImageResponse, BuildReport
    from dockerls.domain.entities.build_validation import ValidationCheck, ValidationResult
    from dockerls.domain.entities.hardening_rule import HardeningRule
    from dockerls.infrastructure.config.hardening import ProjectPolicy

console = Console()

STATUS_STYLE = {
    CheckStatus.PASS: ("[green]PASS[/green]", "green"),
    CheckStatus.WARN: ("[yellow]WARN[/yellow]", "yellow"),
    CheckStatus.FAIL: ("[red]FAIL[/red]", "red"),
    CheckStatus.SKIP: ("[dim]SKIP[/dim]", "dim"),
}

TIER_STYLE = {"S": "bold green", "A": "bold green", "B": "bold yellow", "C": "bold red"}


class FailOn(StrEnum):
    NONE = "none"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


def build(  # noqa: PLR0913 - one flag per documented CLI option
    path: str = typer.Argument(".", help="Build context directory, or a Dockerfile path"),
    tag: str = typer.Option("", "--tag", "-t", help="Image tag to build (e.g. myapp:1.0)"),
    dockerfile: str = typer.Option(
        "", "--file", "-f", help="Dockerfile path (default: <PATH>/Dockerfile)"
    ),
    base: str = typer.Option(
        "", "--base", help=f"Hardened template to use: {', '.join(sorted(TEMPLATES))}"
    ),
    hardened: bool = typer.Option(
        False,
        "--hardened",
        help="Build from a bundled hardened template instead of your Dockerfile",
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Ask for the build options step by step"
    ),
    scan: bool = typer.Option(True, "--scan/--no-scan", help="Scan the image after building"),
    fail_on: FailOn | None = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero on findings at/above this severity "
        "[config: build_fail_on, default critical]",
    ),
    report: str = typer.Option(
        "",
        "--report",
        "-r",
        "--output",
        "-o",
        help="Write the report to this file (format from the extension: .json, .html, .sarif, .md)",
    ),
    report_format: list[str] = typer.Option(  # noqa: B006 - typer builds the list
        [],
        "--format",
        help="Extra report formats written to the report directory "
        f"({', '.join(BuildReportExporterFactory.supported_formats())}); repeatable",
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable the Docker layer cache"),
    build_arg: list[str] = typer.Option(  # noqa: B006
        [], "--build-arg", help="Build argument as KEY=VALUE; repeatable"
    ),
    build_args_json: str = typer.Option(
        "", "--build-args", help='Build arguments as JSON: \'{"KEY":"VALUE"}\''
    ),
    label: list[str] = typer.Option(  # noqa: B006
        [], "--label", help="Image label as KEY=VALUE; repeatable"
    ),
    labels_json: str = typer.Option("", "--labels", help='Labels as JSON: \'{"KEY":"VALUE"}\''),
    secret: list[str] = typer.Option(  # noqa: B006
        [], "--secret", help="BuildKit secret as id=NAME,env=VAR or id=NAME,src=PATH; repeatable"
    ),
    ci_mode: bool = typer.Option(
        False, "--ci-mode", help="Machine-readable JSON on stdout, no interaction, no colour"
    ),
    validate_only: bool = typer.Option(
        False, "--validate-only", help="Validate the Dockerfile and stop; never builds"
    ),
    suggest_hardening: bool = typer.Option(
        False, "--suggest-hardening", help="Show hardening suggestions and stop; never builds"
    ),
    hardening_level: str = typer.Option(
        "",
        "--hardening-level",
        help="strict | standard | relaxed [config: hardening_level, default standard]",
    ),
    force: bool = typer.Option(
        False, "--force", help="Build even when validation found blocking issues"
    ),
    no_sbom: bool = typer.Option(False, "--no-sbom", help="Skip SBOM generation"),
    platform: str = typer.Option("", "--platform", help="Target platform, e.g. linux/arm64"),
    target: str = typer.Option("", "--target", help="Build only up to this named stage"),
    push: bool = typer.Option(False, "--push", help="Push the image after a passing build"),
    config: str = typer.Option(
        "", "--config", help="Policy file (default: nearest .dockerls-hardening.yaml)"
    ),
    batch: bool = typer.Option(
        False, "--batch", help="Build every project listed in the policy file"
    ),
    vault_push: bool = typer.Option(False, "--vault-push", help="Write the report to the vault"),
    vault_path: str = typer.Option(
        "", "--vault-path", help="Path inside the vault, e.g. infraestrutura/containers/myapp"
    ),
    vault_root: str = typer.Option(
        "", "--vault-root", help="Vault root directory [config: vault_root]"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable coloured output"),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Also print logs to stderr (they always go to the log file)"
    ),
) -> None:
    """Build a hardened Docker image: validate, build, scan, report.

    Runs the OWASP Dockerfile rule set before the build, so a Dockerfile
    that leaks a credential never produces an image, and scans the result
    afterwards so the report describes what actually shipped.
    """
    if no_color or ci_mode:
        console.no_color = True
    if verbose:
        enable_console_logging()

    try:
        policy = _load_policy(path, config)
        level = build_hardening_level(hardening_level or policy.validation.hardening_level.value)
    except (HardeningConfigError, ValueError) as e:
        _fail(f"{e}", ci_mode)
        return

    if interactive and not ci_mode:
        tag, base, hardened, scan, report_format, push = _wizard(
            path, tag, base, hardened, scan, list(report_format), push
        )

    default_fail_on, default_buildkit, default_sbom = build_defaults()
    resolved_fail_on = (
        fail_on.value if fail_on is not None else (policy.scanning.fail_on or default_fail_on)
    )
    dry_run = validate_only or suggest_hardening

    try:
        requests = _requests(
            path=path,
            policy=policy,
            batch=batch,
            tag=tag,
            dockerfile=dockerfile,
            base=base,
            hardened=hardened,
            level=level,
            scan=scan and policy.scanning.enabled and not dry_run,
            fail_on=resolved_fail_on,
            report=report,
            report_formats=_report_formats(report_format, policy, ci_mode),
            no_cache=no_cache,
            build_args=_pairs(build_arg, build_args_json, "--build-arg"),
            labels=_pairs(label, labels_json, "--label"),
            secrets=_secrets(secret),
            validate_only=validate_only,
            suggest_only=suggest_hardening,
            force=force,
            generate_sbom=not no_sbom and policy.scanning.sbom and default_sbom and not dry_run,
            buildkit=policy.buildkit.enabled and default_buildkit,
            platform=platform,
            target=target,
            push=push,
            vault_push=vault_push or policy.reporting.vault_push,
            vault_path=vault_path or policy.reporting.vault_path,
        )
    except (ValueError, TemplateGenerationError) as e:
        _fail(str(e), ci_mode)
        return

    exit_code = asyncio.run(
        _run(
            requests,
            level=level,
            skip_rules=policy.validation.skip_rules,
            sbom_formats=tuple(policy.scanning.sbom_formats),
            vault_root=vault_root or policy.reporting.vault_root,
            ci_mode=ci_mode,
        )
    )
    raise typer.Exit(exit_code)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


async def _run(
    requests: list[BuildImageRequest],
    level: HardeningLevel,
    skip_rules: list[str],
    sbom_formats: tuple[str, ...],
    vault_root: str,
    ci_mode: bool,
) -> int:
    # One use case for the whole run: in batch mode this reuses a single
    # scanner (and its warmed Trivy DB) across every project.
    use_case = await build_build_use_case(
        hardening_level=level,
        skip_rules=skip_rules,
        scan=any(r.scan for r in requests),
        sbom_formats=sbom_formats,
        vault_root=vault_root,
    )

    responses: list[BuildImageResponse] = []
    for request in requests:
        try:
            response = await use_case.execute(request)
        except ValueError as e:
            _fail(str(e), ci_mode)
            return EXIT_FAILED
        if request.vault_push:
            await use_case.push_to_vault(response, request.vault_path or "builds")
        responses.append(response)
        if not ci_mode:
            _render(response, request)

    if ci_mode:
        payload = (
            responses[0].report.model_dump(mode="json")
            if len(responses) == 1
            else {"builds": [r.report.model_dump(mode="json") for r in responses]}
        )
        console.print(json.dumps(payload, indent=2, default=str), soft_wrap=True)

    # The worst outcome across the batch decides the exit code: a pipeline
    # that builds five images must fail if any one of them failed.
    return max((r.exit_code for r in responses), default=EXIT_OK)


def _requests(  # noqa: PLR0913 - assembles one request per documented flag
    *,
    path: str,
    policy: HardeningConfig,
    batch: bool,
    tag: str,
    dockerfile: str,
    base: str,
    hardened: bool,
    level: HardeningLevel,
    scan: bool,
    fail_on: str,
    report: str,
    report_formats: list[str],
    no_cache: bool,
    build_args: dict[str, str],
    labels: dict[str, str],
    secrets: list[BuildSecret],
    validate_only: bool,
    suggest_only: bool,
    force: bool,
    generate_sbom: bool,
    buildkit: bool,
    platform: str,
    target: str,
    push: bool,
    vault_push: bool,
    vault_path: str,
) -> list[BuildImageRequest]:
    projects: list[ProjectPolicy | None]
    if batch:
        if not policy.projects:
            raise ValueError(
                "--batch needs a `projects:` list in the policy file "
                f"({policy.source_path or 'none found'})"
            )
        projects = list(policy.projects)
    else:
        projects = [None]

    requests: list[BuildImageRequest] = []
    for project in projects:
        context = Path(project.context if project else path)
        resolved_tag = project.tag if project else tag
        if not resolved_tag and not validate_only and not suggest_only:
            raise ValueError("--tag is required to build (or use --validate-only)")

        resolved_dockerfile = project.dockerfile if project else dockerfile
        template = project.hardened_template if project else base
        if hardened or (project and project.hardened_template):
            resolved_dockerfile = _materialise_template(context, template)

        requests.append(
            BuildImageRequest(
                context_path=str(context),
                dockerfile_path=resolved_dockerfile,
                tag=resolved_tag,
                build_args={**(project.build_args if project else {}), **build_args},
                labels={**(project.labels if project else {}), **labels},
                secrets=secrets,
                hardening_level=level,
                validate_only=validate_only,
                suggest_only=suggest_only,
                force=force,
                scan=scan,
                generate_sbom=generate_sbom,
                fail_on=fail_on,
                no_cache=no_cache,
                buildkit=buildkit,
                platform=platform,
                target=target,
                push=push or bool(project and project.push),
                report_path=report if not project else "",
                report_formats=report_formats,
                vault_push=vault_push,
                vault_path=vault_path or (f"builds/{project.name}" if project else ""),
            )
        )
    return requests


def _materialise_template(context: Path, base: str) -> str:
    """Write the bundled template into the build context and return its path.

    Written into the context rather than a temp file on purpose: the file a
    build used must stay on disk afterwards, or nobody can review what was
    actually built.
    """
    generator = build_template_generator(build_hardening_level())
    target = context / DEFAULT_OUTPUT_NAME
    result = generator.execute(context, base=base, output=target, force=True)
    console.print(
        f"[dim]Using hardened {result.template} template -> {result.dockerfile_path}[/dim]"
    )
    return result.dockerfile_path


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------


def _load_policy(path: str, config: str) -> HardeningConfig:
    explicit = Path(config) if config else None
    if explicit is not None and not explicit.is_file():
        raise HardeningConfigError(f"Policy file not found: {config}")
    return load_hardening_config(explicit or find_hardening_config(Path(path)))


def _pairs(items: list[str], as_json: str, flag: str) -> dict[str, str]:
    """Merge the repeatable `KEY=VALUE` form with the JSON form.

    Explicit `--build-arg` wins over `--build-args` JSON: the one written
    last on the command line is the one the user was thinking about.
    """
    result: dict[str, str] = {}
    if as_json:
        try:
            parsed = json.loads(as_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"{flag}s is not valid JSON: {e}") from e
        if not isinstance(parsed, dict):
            raise ValueError(f"{flag}s must be a JSON object of key/value pairs")
        result.update({str(k): str(v) for k, v in parsed.items()})
    for item in items:
        if "=" not in item:
            raise ValueError(f"{flag} must be KEY=VALUE, got: {item}")
        key, _, value = item.partition("=")
        result[key.strip()] = value
    return result


def _secrets(items: list[str]) -> list[BuildSecret]:
    secrets: list[BuildSecret] = []
    for item in items:
        fields = dict(part.split("=", 1) for part in item.split(",") if "=" in part)
        secret_id = fields.get("id", "").strip()
        if not secret_id:
            raise ValueError(f"--secret needs an id=, got: {item}")
        env = fields.get("env", "").strip()
        src = fields.get("src", fields.get("source", "")).strip()
        if not env and not src:
            raise ValueError(f"--secret {secret_id} needs env= or src=")
        secrets.append(BuildSecret(secret_id=secret_id, env=env, file=src))
    return secrets


def _report_formats(requested: list[str], policy: HardeningConfig, ci_mode: bool) -> list[str]:
    formats = [f.lower() for f in requested] or list(policy.reporting.formats)
    # CI reads the JSON on stdout, but the SARIF file is what gets uploaded
    # to the security tab, so a CI run always writes one.
    if ci_mode and "sarif" not in formats:
        formats.append("sarif")
    return formats


def _wizard(
    path: str,
    tag: str,
    base: str,
    hardened: bool,
    scan: bool,
    report_format: list[str],
    push: bool,
) -> tuple[str, str, bool, bool, list[str], bool]:
    """The `--interactive` walkthrough.

    Only asks what it cannot work out: a flag already given on the command
    line is never re-asked, so `--interactive --tag x` does not prompt for
    the tag.
    """
    console.print(Panel("[bold]DockerLs secure build[/bold]", expand=False))

    if not base:
        detected = build_template_generator(build_hardening_level()).detect(Path(path))
        choices = sorted(TEMPLATES)
        default = detected or choices[0]
        base = typer.prompt(
            f"Application type ({'/'.join(choices)})",
            default=default,
        ).strip()
    if not hardened:
        hardened = typer.confirm("Use the bundled hardened template?", default=True)
    if not tag:
        tag = typer.prompt("Image tag (e.g. myapp:1.0)").strip()
    scan = typer.confirm("Scan the image after building?", default=scan)
    if not report_format:
        answer = typer.prompt("Report format (json/html/both/none)", default="json").strip().lower()
        report_format = {
            "json": ["json"],
            "html": ["html"],
            "both": ["json", "html"],
            "none": [],
        }.get(answer, ["json"])
    push = typer.confirm("Push to the registry after a passing build?", default=push)
    return tag, base, hardened, scan, report_format, push


def _fail(message: str, ci_mode: bool) -> None:
    if ci_mode:
        console.print(
            json.dumps({"status": "FAILED", "code": EXIT_FAILED, "reason": message}, indent=2),
            soft_wrap=True,
        )
    else:
        console.print(f"[red]Build aborted:[/red] {message}")
    raise typer.Exit(EXIT_FAILED)


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------


def _render(response: BuildImageResponse, request: BuildImageRequest) -> None:
    report = response.report
    console.print(
        Panel(
            f"[bold]DockerLs -- Secure Build & Scan Report[/bold]\n"
            f"[dim]{report.dockerfile_path}  ->  {report.image or '(validate only)'}[/dim]",
            expand=False,
        )
    )
    _print_validation(report.validation)

    if report.build is not None:
        _print_build(report)
    if report.scans:
        _print_scans(report)
    if report.recommendations:
        _print_recommendations(report.recommendations)
    if report.sbom is not None and report.sbom.file:
        console.print(
            f"\n[bold]SBOM[/bold]\n  {report.sbom.file} "
            f"[dim]({report.sbom.components_count} components, {report.sbom.fmt})[/dim]"
        )
    _print_verdict(response, request)


def _print_validation(validation: ValidationResult) -> None:
    passed = len(validation.passed)
    total = validation.evaluated_count
    console.print(f"\n[bold]Dockerfile Validation[/bold]  [dim]({passed}/{total} passed)[/dim]\n")

    table = Table(show_header=True)
    table.add_column("Rule", style="cyan", overflow="fold")
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Sev", justify="center", no_wrap=True)
    table.add_column("Line", justify="right", style="dim", no_wrap=True)
    table.add_column("Detail", overflow="fold")

    for check in validation.checks:
        marker, _ = STATUS_STYLE[check.status]
        table.add_row(
            check.check,
            marker,
            check.severity.value[:4],
            str(check.line) if check.line else "-",
            check.message,
        )
    console.print(table)

    _print_fixes(validation)


def _print_fixes(validation: ValidationResult) -> None:
    """Print the remediation for every finding, once, below the table.

    Fixes are multi-line shell and Dockerfile snippets; putting them in a
    table cell makes them unreadable and un-copyable.
    """
    findings: list[ValidationCheck] = [*validation.failures, *validation.warnings]
    findings = [c for c in findings if c.fix]
    if not findings:
        return
    console.print("\n[bold]How to fix[/bold]")
    for check in findings:
        location = f" (line {check.line})" if check.line else ""
        console.print(f"\n  [cyan]{check.check}[/cyan]{location}")
        for fix_line in check.fix.splitlines():
            console.print(f"    [green]{fix_line}[/green]")


def _print_build(report: BuildReport) -> None:
    build = report.build
    if build is None:
        return
    console.print("\n[bold]Build[/bold]")
    if not build.success:
        console.print(f"  [red]FAILED[/red]  {build.error}")
        if build.log_tail:
            console.print("[dim]  --- last lines of the build log ---[/dim]")
            for line in build.log_tail.splitlines()[-15:]:
                console.print(f"  [dim]{line}[/dim]")
        return
    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column("Key", style="bold")
    info.add_column("Value")
    info.add_row("Status", "[green]SUCCESS[/green]")
    info.add_row("Image", build.image_id[:24] or "-")
    info.add_row("Size", build.size_human)
    info.add_row("Layers", str(build.layer_count))
    info.add_row("Duration", f"{build.duration_seconds}s")
    info.add_row("BuildKit", "enabled" if build.buildkit_used else "disabled")
    console.print(info)


def _print_scans(report: BuildReport) -> None:
    console.print("\n[bold]Security Scanning[/bold]")
    table = Table()
    table.add_column("Scanner", style="cyan")
    table.add_column("Critical", justify="right")
    table.add_column("High", justify="right")
    table.add_column("Medium", justify="right")
    table.add_column("Low", justify="right")
    table.add_column("Fixable", justify="right", style="green")
    table.add_column("Status", justify="center")
    for scan in report.scans:
        crit = f"[red]{scan.critical}[/red]" if scan.critical else "0"
        high = f"[yellow]{scan.high}[/yellow]" if scan.high else "0"
        table.add_row(
            scan.scanner,
            crit,
            high,
            str(scan.medium),
            str(scan.low),
            str(scan.fixable),
            scan.status,
        )
    console.print(table)

    if report.failing_vulnerabilities:
        console.print("\n[bold red]Findings above the fail-on threshold[/bold red]")
        vtable = Table()
        vtable.add_column("CVE", style="cyan")
        vtable.add_column("Severity")
        vtable.add_column("Package")
        vtable.add_column("Installed")
        vtable.add_column("Fix")
        for vuln in report.failing_vulnerabilities[:20]:
            fix = vuln.fixed_version or (
                "[green]available[/green]" if vuln.fixable else "[red]none[/red]"
            )
            vtable.add_row(vuln.cve, vuln.severity, vuln.package, vuln.installed_version, fix)
        console.print(vtable)
        remaining = len(report.failing_vulnerabilities) - 20
        if remaining > 0:
            console.print(f"[dim]  ... and {remaining} more (see the report file)[/dim]")


def _print_recommendations(recommendations: list[HardeningRule]) -> None:
    console.print("\n[bold]Recommendations[/bold]")
    for rec in recommendations:
        style = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}[rec.priority.value]
        console.print(f"  [{style}]{rec.priority.value:<6}[/{style}] {rec.title}")
        console.print(f"         [dim]{rec.reason}[/dim]")
        if rec.current and rec.suggested and "\n" not in rec.suggested:
            console.print(f"         [dim]{rec.current}[/dim] -> [green]{rec.suggested}[/green]")


def _print_verdict(response: BuildImageResponse, request: BuildImageRequest) -> None:
    report = response.report
    tier_style = TIER_STYLE.get(report.security_tier, "")
    console.print(
        f"\n[bold]Score[/bold] {report.security_score}/100   "
        f"[bold]Tier[/bold] [{tier_style}]{report.security_tier}[/{tier_style}] "
        f"[dim]({report.tier_advice})[/dim]"
    )
    if report.scan_score is not None:
        console.print(
            f"[dim]  dockerfile {report.dockerfile_score} | scan {report.scan_score}[/dim]"
        )
    else:
        # Without a scan the number rates the Dockerfile alone. Saying so
        # stops a clean "100/100 Tier S" from being read as a statement
        # about an image whose contents were never measured.
        console.print(
            "[dim]  no image scan ran -- this rates the Dockerfile only, "
            "not the packages in the image[/dim]"
        )

    for path in response.written_reports:
        console.print(f"[dim]report: {path}[/dim]", soft_wrap=True)
    if response.vault_note:
        console.print(f"[dim]vault: {response.vault_note}[/dim]", soft_wrap=True)
    if response.push_message:
        style = "green" if response.pushed else "yellow"
        console.print(f"[{style}]push: {response.push_message}[/{style}]", soft_wrap=True)
    if report.log_file:
        console.print(f"[dim]log: {report.log_file}[/dim]", soft_wrap=True)

    if report.status == "FAILED":
        console.print(f"\n[bold red]FAILED[/bold red] -- {report.reason}")
        if report.validation.has_blocking_findings and not request.force:
            console.print(
                "[dim]Fix the findings above, lower --hardening-level, or re-run "
                "with --force to build anyway.[/dim]"
            )
    elif report.status == "WARNING":
        console.print(f"\n[bold yellow]REVIEW[/bold yellow] -- {report.reason}")
    elif request.validate_only or request.suggest_only:
        console.print("\n[bold green]PASS[/bold green] -- Dockerfile clears every rule.")
    else:
        console.print("\n[bold green]PASS[/bold green] -- image is ready for production.")
