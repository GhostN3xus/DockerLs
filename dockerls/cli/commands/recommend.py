from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls import __version__
from dockerls import cli as cli_package
from dockerls.application.services.ci_summary import build_ci_summary
from dockerls.application.services.decision_summary import (
    DecisionSummary,
    summarize_recommendation,
)
from dockerls.application.services.events import EventStream, NdjsonSink
from dockerls.application.services.instrumentation import RunInstrumentation
from dockerls.application.services.run_diff import RunDiff, diff_runs
from dockerls.application.services.source_registry import UnknownSourceError
from dockerls.cli.decision_view import render_decision
from dockerls.cli.dependencies import (
    build_recommend_use_case,
    build_run_store,
    enable_console_logging,
    resolve_tag_limit,
)
from dockerls.cli.image_names import display_reference, reject_tagged_reference
from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.progress import RichScanObserver
from dockerls.cli.run_diff_view import print_run_diff
from dockerls.cli.run_options import RunOptions, parse_run_options
from dockerls.cli.scan_failure import short_reason
from dockerls.cli.text import safe
from dockerls.cli.validators import check_limit, check_threshold, check_workers
from dockerls.domain.value_objects.confidence import Confidence
from dockerls.domain.value_objects.security_tier import SecurityTier, Tier
from dockerls.domain.value_objects.tristate import Tristate
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, exit_code_for_completeness
from dockerls.infrastructure.evidence import slugify_reference
from dockerls.infrastructure.run_store import RunStore, scope_of
from dockerls.utils.deadline import Deadline

if TYPE_CHECKING:
    from collections.abc import Callable

    from dockerls.application.dto.analysis import (
        AnalysisResult,
        DimensionReport,
        ImageAnalysis,
    )

console = Console()

# Exit codes, in order of severity:
#   0 = an image meeting the baseline (Critical=0, High=0, Medium<=max) was found
#   1 = a hard error occurred (nothing could be scanned, or --fail-on was violated)
#   2 = no baseline image, but fallback alternatives were found
#   3 = nothing usable was found at all
# 0 e 1 vêm do contrato compartilhado; 2 e 3 são próprios de `recommend`,
# que escolhe entre candidatos em vez de avaliar um artefato do usuário.
EXIT_BASELINE_MET = EXIT_OK
EXIT_ERROR_CODE = EXIT_ERROR
EXIT_ALTERNATIVES_FOUND = 2
EXIT_NONE_FOUND = 3

RECOMMEND_FORMATS = (
    OutputFormat.TABLE,
    OutputFormat.JSON,
    OutputFormat.NDJSON,
    OutputFormat.SUMMARY,
)

DISPUTED_SCORE_LABEL = "[yellow]!disputed[/yellow]"


class FailOn(StrEnum):
    NONE = "none"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


_FAIL_ON_COUNT: dict[FailOn, Callable[[ImageAnalysis], int]] = {
    FailOn.CRITICAL: lambda a: a.scan.critical_count,
    FailOn.HIGH: lambda a: a.scan.critical_count + a.scan.high_count,
    FailOn.MEDIUM: lambda a: a.scan.critical_count + a.scan.high_count + a.scan.medium_count,
}


def recommend(
    image: str = typer.Argument(
        help=(
            "Docker image name only, without a tag (e.g. 'node', not 'node:18'). "
            "Use 'analyze' or 'advisor' for a specific tag."
        )
    ),
    max_critical: int | None = typer.Option(
        None, "--max-critical", help="Max critical vulns allowed [config: max_critical, default 0]"
    ),
    max_high: int | None = typer.Option(
        None, "--max-high", help="Max high vulns allowed [config: max_high, default 0]"
    ),
    max_medium: int | None = typer.Option(
        None, "--max-medium", help="Max medium vulns allowed [config: max_medium, default 5]"
    ),
    limit: int | None = typer.Option(
        None, "--limit", "-l", help="Max tags to discover [config: max_tags, default 100]"
    ),
    budget: int | None = typer.Option(
        None,
        "--budget",
        "-b",
        help="Max tags to actually scan; 0 scans every tag found [config: scan_budget, default 25]",
    ),
    workers: int | None = typer.Option(
        None,
        "--workers",
        "-w",
        help="Concurrent scanner processes; 0 sizes it to this machine [config: workers]",
    ),
    fail_on: FailOn = typer.Option(
        FailOn.NONE, "--fail-on", help="Exit non-zero if the top result has vulns at/above severity"
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Output format: table or json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
    no_progress: bool = typer.Option(False, "--no-progress", help="Disable the progress display"),
    cross_validate: bool | None = typer.Option(
        None,
        "--cross-validate/--no-cross-validate",
        help="Second-scanner validation of the top candidates [default: on, or per --profile]",
    ),
    hub_check: bool | None = typer.Option(
        None,
        "--hub-check/--no-hub-check",
        help="Registry tag existence verification [default: on, or per --profile]",
    ),
    no_hardened: bool = typer.Option(
        False, "--no-hardened", help="Search Docker Hub only (skip Chainguard/Distroless)"
    ),
    source: list[str] = typer.Option(
        [],
        "--source",
        "-s",
        help=(
            "Image source to search; repeatable. "
            "One of: dockerhub, chainguard, distroless, dhi, private (if configured), all"
        ),
    ),
    all_sources: bool = typer.Option(
        False, "--all-sources", help="Search every configured source, including opt-in ones"
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Ignore cached analyses and re-scan every candidate"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Also print logs to stderr (they always go to the log file)"
    ),
    platform: str | None = typer.Option(
        None,
        "--platform",
        help="os/architecture, with an optional /variant, e.g. linux/arm64 (default: linux/amd64)",
    ),
    time_budget: str | None = typer.Option(
        None,
        "--time-budget",
        help=(
            "Total seconds for the whole run. When it ends first the measurements already "
            "done are shown as PARTIAL (exit 5), or exit 4 if there are none"
        ),
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="quick | standard | audit: how much to measure and verify (see docs/PROFILES.md)",
    ),
    runtime_version: str | None = typer.Option(
        None,
        "--runtime-version",
        help="Only tags in this runtime version or range: 22, 22.5, '>=20,<23' or 20-22",
    ),
    distro: str | None = typer.Option(
        None, "--distro", help="Only this distribution family: alpine, debian, ubuntu, wolfi, ..."
    ),
    variant: str | None = typer.Option(
        None, "--variant", help="Only runtime or dev variants of an image"
    ),
    details: bool = typer.Option(
        False, "--details", help="Also show the reasoning, per-image evidence and diagnostics"
    ),
    diff: bool = typer.Option(
        False,
        "--diff",
        help="Show findings that are new or gone since the previous compatible run",
    ),
) -> None:
    """Recommend the most secure Docker image tags."""
    if no_color:
        console.no_color = True
    if verbose:
        enable_console_logging()
    fmt = parse_output_format(output_format, RECOMMEND_FORMATS)
    options = parse_run_options(
        platform=platform,
        time_budget=time_budget,
        profile=profile,
        runtime_version=runtime_version,
        distro=distro,
        variant=variant,
    )

    # Validated here, before any dependency is built: an out-of-range value
    # must produce a readable CLI error rather than a traceback from deep
    # inside the use case (or, for `--workers 0`, a semaphore nobody can
    # acquire). `None` means "not given", so the configured default applies.
    if max_critical is not None:
        max_critical = check_threshold(max_critical, "max_critical")
    if max_high is not None:
        max_high = check_threshold(max_high, "max_high")
    if max_medium is not None:
        max_medium = check_threshold(max_medium, "max_medium")
    if limit is not None:
        limit = check_limit(limit)
    # `0` é um valor legítimo aqui -- significa "meça todas" -- e por isso
    # não passa pelo validador de limite, que recusa zero.
    if budget is not None and budget < 0:
        raise typer.BadParameter("--budget cannot be negative")
    # `0` means "size it to this machine", so it is passed through rather
    # than validated: the resolver, not the flag, decides what it becomes.
    if workers:
        workers = check_workers(workers)

    error = reject_tagged_reference(image, "recommend")
    if error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(EXIT_ERROR_CODE)

    try:
        asyncio.run(
            _recommend(
                image,
                max_critical,
                max_high,
                max_medium,
                limit,
                budget,
                workers,
                fail_on,
                fmt,
                show_progress=not no_progress and fmt is OutputFormat.TABLE,
                # Without a profile these keep their historical meaning (on
                # unless switched off); with one, only an explicit flag
                # overrides what the profile says.
                cross_validate=(
                    cross_validate
                    if cross_validate is not None
                    else (None if options.profile is not None else True)
                ),
                verify_hub_tags=(
                    hub_check
                    if hub_check is not None
                    else (None if options.profile is not None else True)
                ),
                include_hardened=not no_hardened,
                use_cache=not no_cache,
                sources=list(source) or None,
                all_sources=all_sources,
                options=options,
                details=details,
                diff=diff,
            )
        )
    except UnknownSourceError as e:
        # Its own arm: a mistyped source names a fixable mistake, and the
        # exception already carries the valid choices.
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(EXIT_ERROR_CODE) from e
    except ValueError as e:
        # Bad thresholds are user error, not a crash: show the message, not
        # a stack trace (pretty_exceptions_enable is off app-wide).
        console.print(f"[red]Invalid configuration:[/red] {e}")
        raise typer.Exit(EXIT_ERROR_CODE) from e


async def _recommend(
    image: str,
    max_critical: int | None,
    max_high: int | None,
    max_medium: int | None,
    limit: int | None,
    budget: int | None,
    workers: int | None,
    fail_on: FailOn,
    output_format: OutputFormat,
    show_progress: bool = True,
    cross_validate: bool | None = True,
    verify_hub_tags: bool | None = True,
    include_hardened: bool = True,
    use_cache: bool = True,
    sources: list[str] | None = None,
    all_sources: bool = False,
    options: RunOptions | None = None,
    details: bool = False,
    diff: bool = False,
) -> None:
    options = options or parse_run_options()
    # The clock starts here, before anything is built: the budget covers
    # discovery, database preparation, scans, retries, enrichment and the
    # final checks -- everything a run does.
    deadline = Deadline(options.time_budget) if options.time_budget else Deadline.unbounded()
    instrumentation = RunInstrumentation()
    instrumentation.add("startup", cli_package.startup_seconds())
    run_id = RunStore.new_run_id()
    streaming = output_format is OutputFormat.NDJSON
    events = EventStream(
        [NdjsonSink(sys.stdout)] if streaming else [], command="recommend", run_id=run_id
    )

    # The observer builds its own stderr console; `console` (stdout) is left
    # exclusively for results so the two streams cannot interleave.
    with RichScanObserver(enabled=show_progress) as observer:
        # Shown before anything else: `build_recommend_use_case` resolves
        # sources and probes the scanner, which can touch the network
        # before a single tag is even discovered. Without this line the
        # terminal stayed blank for that whole stretch -- no spinner, no
        # text -- which read as a hang rather than as setup in progress.
        observer.phase("Initializing")
        use_case = await build_recommend_use_case(
            max_critical=max_critical,
            max_high=max_high,
            max_medium=max_medium,
            workers=workers,
            observer=observer,
            cross_validate=cross_validate,
            verify_hub_tags=verify_hub_tags,
            include_hardened=include_hardened,
            use_cache=use_cache,
            sources=sources,
            all_sources=all_sources,
            scan_budget=budget,
            platform=options.platform,
            deadline=deadline,
            instrumentation=instrumentation,
            profile=options.profile,
            criteria=options.criteria,
            events=events,
        )
        result = await use_case.execute(image, limit=resolve_tag_limit(limit))

    violation = _fail_on_violated(result, fail_on)
    code = exit_code_for_completeness(
        _exit_code(result, fail_on), result.completeness, violation=violation
    )
    summary = summarize_recommendation(result)
    saved = _save_run(result, summary, options, run_id)
    previous_diff = _diff_against_previous(saved, diff)

    if output_format is OutputFormat.NDJSON:
        # Everything was already streamed; the final event carried the result.
        raise typer.Exit(code)

    if output_format is OutputFormat.SUMMARY:
        ci = build_ci_summary(
            summary,
            command="recommend",
            exit_code=code,
            run_id=saved.get("run_id", "") if saved else "",
            baseline=result.baseline.model_dump() if result.baseline else None,
        )
        sys.stdout.write(json.dumps(ci.model_dump(by_alias=True), indent=2, default=str) + "\n")
        raise typer.Exit(code)

    if output_format == OutputFormat.JSON:
        payload = result.model_dump()
        payload["summary"] = summary.model_dump(mode="json")
        payload["run_id"] = saved.get("run_id", "") if saved else ""
        if previous_diff is not None:
            payload["diff"] = previous_diff.model_dump(mode="json")
        console.print(json.dumps(payload, indent=2, default=str), soft_wrap=True)
        raise typer.Exit(code)

    render_decision(console, summary)
    _print_summary(result)

    if result.baseline_met and result.recommendations:
        console.print(Panel("[bold green]Recommended Images[/bold green]", expand=False))
        _print_table(result.recommendations)
        if details:
            _print_why(result.recommendations)
            _print_details(result.recommendations)
        _print_divergences(result.recommendations)
    elif result.alternatives:
        console.print(Panel(_baseline_miss_message(result), expand=False))
        _print_table(result.alternatives)
        if details:
            _print_why(result.alternatives)
            _print_details(result.alternatives)
        _print_divergences(result.alternatives)
    elif result.filters_note:
        console.print(f"[yellow]{safe(result.filters_note)}[/yellow]")
    elif _nothing_could_be_measured(result):
        console.print(_measurement_failure_message(result))
    elif result.completeness == "NO_RESULT":
        console.print("[yellow]The time budget ended before anything was measured.[/yellow]")
    else:
        console.print("[red]No suitable images found.[/red]")
        console.print(f"[dim]{_baseline_line(result)}[/dim]")

    _print_tier_warnings(result.recommendations or result.alternatives)
    _print_unverified(result)
    _print_deferred(result)
    _print_excluded(result, details)
    if previous_diff is not None:
        print_run_diff(console, previous_diff)
    if details:
        _print_diagnostics(result)

    if result.evidence_manifest:
        console.print(f"\n[dim]Evidence manifest: {result.evidence_manifest}[/dim]")
    if saved:
        console.print(
            f"[dim]Run id: {saved['run_id']} (export it again with "
            f"`dockerls export --run {saved['run_id']}`)[/dim]"
        )

    raise typer.Exit(code)


def _fail_on_violated(result: AnalysisResult, fail_on: FailOn) -> bool:
    items = result.recommendations or result.alternatives
    if not items or fail_on == FailOn.NONE:
        return False
    return _FAIL_ON_COUNT[fail_on](items[0]) > 0


def _save_run(
    result: AnalysisResult, summary: DecisionSummary, options: RunOptions, run_id: str
) -> dict[str, str]:
    """Keep the run so a later command can diff against it or export it.

    Best effort: failing to save never changes the outcome of the run.
    """
    try:
        store = build_run_store()
        saved_id = store.save(
            command="recommend",
            query=result.query,
            platform=str(options.platform),
            filters=result.filters,
            profile=result.profile,
            completeness=result.completeness,
            result=result.model_dump(mode="json"),
            summary=summary.model_dump(mode="json"),
            version=__version__,
            run_id=run_id,
        )
    except Exception as e:
        logger.warning(f"Could not save the run: {e}")
        return {}
    return {"run_id": saved_id} if saved_id else {}


def _diff_against_previous(saved: dict[str, str], wanted: bool) -> RunDiff | None:
    if not wanted or not saved:
        return None
    try:
        store = build_run_store()
        current = store.load(saved["run_id"])
        if current is None:
            return None
        previous = store.previous_compatible(current, scope_of(current))
    except Exception as e:
        logger.warning(f"Could not compare with the previous run: {e}")
        return None
    if previous is None:
        return RunDiff(
            compatible=False, note="there is no earlier run that asked the same question"
        )
    return diff_runs(previous, current)


def _print_excluded(result: AnalysisResult, details: bool) -> None:
    """What the compatibility filters removed, and how each was decided."""
    if not result.excluded:
        return
    heuristic = sum(1 for e in result.excluded if e.basis.value == "HEURISTIC")
    console.print(
        f"\n[bold]Filtered out before scanning[/bold] ({len(result.excluded)} tags; "
        f"{len(result.excluded) - heuristic} confirmed, {heuristic} judged from tag names)"
    )
    shown = result.excluded if details else result.excluded[:5]
    for item in shown:
        console.print(
            f"  [dim]{safe(item.reference)}[/dim] -- {safe(item.criterion)}: "
            f"{safe(item.reason)} [{item.basis.value.lower()}]"
        )
    if len(result.excluded) > len(shown):
        console.print(f"  [dim]... and {len(result.excluded) - len(shown)} more (--details)[/dim]")
    if result.enrichment_note:
        console.print(f"[yellow]{safe(result.enrichment_note)}[/yellow]")


def _print_diagnostics(result: AnalysisResult) -> None:
    """Timings, request counts and cache notes: what the run *did*."""
    timings = result.metrics.timings
    console.print("\n[bold]Diagnostics[/bold]")
    console.print(
        f"  profile: {result.profile or 'default'} | platform: {safe(result.platform)} | "
        f"completeness: {result.completeness} | elapsed: {result.elapsed_seconds}s"
        + (f" of {result.time_budget_seconds}s budget" if result.time_budget_seconds else "")
    )
    if result.metrics.scanner_identity:
        console.print(
            f"  scanner: {safe(result.metrics.scanner_identity)} | database revision: "
            f"{safe(result.metrics.db_revision) or 'unknown'}"
        )
    if timings:
        first = timings.get("time_to_first_result_seconds")
        console.print(
            f"  time to first useful result: {first if first is not None else 'n/a'}s | "
            f"total: {timings.get('total_seconds')}s"
        )
        for stage, data in timings.get("stages", {}).items():
            console.print(f"    {stage:<24} {data['seconds']:>8.3f}s  ({data['calls']} call(s))")
        console.print("  [dim]stages overlap, so they do not sum to the total[/dim]")
        requests = timings.get("requests_by_source", {})
        if requests:
            console.print(
                "  requests: " + ", ".join(f"{k}={v}" for k, v in sorted(requests.items()))
            )
        counters = timings.get("counters", {})
        if counters:
            console.print("  " + ", ".join(f"{k}={v}" for k, v in sorted(counters.items())))
    for analysis in (result.recommendations or result.alternatives)[:5]:
        prov = analysis.provenance
        console.print(
            f"  {safe(analysis.image.full_reference)}: {prov.origin}, requested "
            f"{safe(prov.requested_reference) or '-'} -> resolved "
            f"{safe(prov.resolved_reference) or 'not confirmed'} -> measured "
            f"{safe(prov.measured_reference) or '-'}"
            + (f"; cache: {safe(prov.cache_note)}" if prov.cache_note else "")
        )


def _baseline_line(result: AnalysisResult) -> str:
    if result.baseline is None:
        return ""
    return f"Baseline: {result.baseline.describe()}."


def _baseline_miss_message(result: AnalysisResult) -> str:
    """Name the exact threshold that was not met, so "no match" is a fact
    the reader can check rather than an opaque verdict.

    O ranking abaixo do alvo é apresentado como tal, e com todas as letras:
    são as melhores candidatas encontradas, nenhuma delas aprovada. Antes o
    caminho alternativo exigia `critical_count == 0` -- o mesmo critério que o
    baseline acabara de rejeitar --, então quando toda tag tinha um CRITICAL o
    usuário recebia "No suitable images found" e nada mais, depois de esperar
    por uma centena de scans.
    """
    baseline = _baseline_line(result)
    detail = f"{baseline}\n" if baseline else ""
    return (
        f"[bold yellow]No image meets the baseline.[/bold yellow]\n"
        f"[yellow]{detail}"
        f"Showing the best candidates found -- all of them below target.[/yellow]"
    )


def _print_summary(result: AnalysisResult) -> None:
    """One-line account of the run, so a clean table can never hide the
    fact that half the candidates failed to scan."""
    analyzed = result.total_tags_analyzed
    total = result.total_tags_scanned
    skipped = result.unverified_count

    parts = [f"[green]OK {analyzed}/{total} analyzed[/green]"]
    if skipped:
        parts.append(f"[yellow]X {skipped} skipped (technical error)[/yellow]")
    if result.deferred_count:
        # Dito no mesmo lugar que os scans que falharam, e com palavras
        # diferentes: um scan que falhou é uma medição que não deu certo,
        # uma tag adiada é uma medição que nem foi tentada. As duas são
        # ausência de medição, e nenhuma é um veredito sobre a imagem.
        parts.append(f"[cyan]- {result.deferred_count} not measured[/cyan]")
    if result.sources_searched:
        parts.append(f"[magenta]sources: {', '.join(result.sources_searched)}[/magenta]")
    console.print(" | ".join(parts))

    work = _work_line(result)
    if work:
        # Second line rather than more fields on the first: the first line
        # answers "what did it find", this one answers "what did it do",
        # and cramming both together made neither readable at 80 columns.
        console.print(work)
    if result.log_file:
        # Its own line: a wrapped path is a path the user cannot copy.
        console.print(f"[dim]log: {result.log_file}[/dim]", soft_wrap=True)
    console.print()


def _work_line(result: AnalysisResult) -> str:
    """Account for the work the run did, not just what it found.

    "Analyzed 84/100" says nothing about whether those 84 cost 84 scans or
    5, which is the difference between four minutes and twenty seconds. The
    numbers were already being computed and thrown away.
    """
    m = result.metrics
    if not m.tags_discovered:
        return ""

    parts = [f"scans: {m.scans_performed}"]
    if m.cache_hits:
        parts.append(f"cache: {m.cache_hits} hit ({m.cache_hit_rate:.0%})")
    if m.duplicates_collapsed:
        parts.append(f"deduped: {m.duplicates_collapsed}")
    if m.cross_validations:
        parts.append(f"cross-validated: {m.cross_validations}")
    if m.workers:
        parts.append(f"workers: {m.workers}")
    return f"[dim]{' | '.join(parts)}[/dim]"


def _hub_status(analysis: ImageAnalysis) -> str:
    if analysis.hub_tag_verified is True:
        return "[green]OK[/green]"
    if analysis.hub_tag_verified is False:
        return "[red]missing[/red]"
    return "[dim]n/a[/dim]"


def _print_table(analyses: list[ImageAnalysis]) -> None:
    # Kept deliberately narrow so it survives an 80-column terminal without
    # ellipsizing the image reference -- the one cell the reader must be
    # able to copy verbatim. Severity counts collapse into a single
    # Critical/High/Medium cell, and full Hub URLs are listed below.
    table = Table()
    table.add_column("#", justify="right", style="dim")
    table.add_column("Image", style="cyan bold", overflow="fold")
    table.add_column("Source", style="magenta")
    table.add_column("Score", justify="right", style="green", no_wrap=True)
    table.add_column("Tier", justify="center")
    table.add_column("C/H/M", justify="center", no_wrap=True)
    table.add_column("Hard", justify="right", no_wrap=True)
    table.add_column("Surf", justify="right", no_wrap=True)
    table.add_column("Conf", justify="center", no_wrap=True)
    table.add_column("Fix", justify="right", style="green")
    table.add_column("Rem", justify="right")
    table.add_column("Tag", justify="center")
    table.add_column("Threat", justify="center", no_wrap=True)

    styles = {
        "A": "bold green",
        "B": "bold blue",
        "C": "bold yellow",
        "D": "bold red",
        "E": "bold red",
        "F": "bold white on red",
    }
    for i, a in enumerate(analyses, 1):
        ts = styles.get(a.tier, "")
        # A score two scanners disagree about is not shown as a number:
        # displaying it would imply a confidence the data does not support.
        score = DISPUTED_SCORE_LABEL if a.scan_divergence else str(a.security_score)
        crit_style = "red" if a.scan.critical_count else "dim"
        counts = (
            f"[{crit_style}]{a.scan.critical_count}[/{crit_style}]/"
            f"[yellow]{a.scan.high_count}[/yellow]/{a.scan.medium_count}"
        )
        table.add_row(
            str(i),
            safe(display_reference(a.image.name, a.image.tag)),
            safe(a.image.source),
            score,
            f"[{ts}]{a.tier}[/{ts}]" if ts else a.tier,
            counts,
            _dimension(a.hardening),
            _dimension(a.attack_surface),
            _confidence_label(a.confidence),
            str(a.scan.fixable_count),
            f"{a.remediation_score}/100",
            _hub_status(a),
            _threat_cell(a),
        )
    console.print(table)
    console.print(
        "[dim]C/H/M = Critical/High/Medium | Hard = hardening (higher is better) | "
        "Surf = attack surface (LOWER is better) | Conf = evidence confidence | "
        "Fix = fixable | Rem = remediation | Tag = confirmed in source registry | "
        "Threat = KEV (actively exploited) / EDB (public exploit) findings, from "
        "CISA KEV, FIRST EPSS and Exploit-DB[/dim]"
    )


def _threat_cell(analysis: ImageAnalysis) -> str:
    """Worst-case KEV/Exploit-DB signal across the image's findings, in one cell.

    The two exploitability signals -- CISA KEV (actively exploited) and
    Exploit-DB (a public exploit exists) -- were already being fetched and
    folded into the security score, but never shown in this table: a reader
    had no way to tell a score reflected them at all. `-` means neither
    catalogue was consulted for any finding in this image (nothing to show
    yet); `none` means they were consulted and found nothing.
    """
    vulns = analysis.scan.vulnerabilities
    if not vulns:
        return "[dim]-[/dim]"
    kev = sum(1 for v in vulns if v.kev_status.is_true)
    edb = sum(1 for v in vulns if v.exploitdb_status.is_true)
    if kev and edb:
        return f"[red bold]KEV:{kev}+EDB:{edb}[/red bold]"
    if kev:
        return f"[red bold]KEV:{kev}[/red bold]"
    if edb:
        return f"[yellow]EDB:{edb}[/yellow]"
    checked = any(
        v.kev_status is not Tristate.UNKNOWN or v.exploitdb_status is not Tristate.UNKNOWN
        for v in vulns
    )
    return "[dim]none[/dim]" if checked else "[dim]-[/dim]"


def _dimension(report: DimensionReport) -> str:
    """Render a dimension, or say plainly that too little was determined.

    A score computed from two facts out of nine is not a measurement, and
    printing it as a number would let the reader treat it as one. Below the
    reportable threshold the cell says `n/a` and the coverage is shown in
    the details section instead.
    """
    if not report.reportable:
        return "[dim]n/a[/dim]"
    return f"{report.score:.0f}"


#: Colours track trust, not quality: UNVERIFIED is red because nothing was
#: measured, which is a stronger warning than a low score.
_CONFIDENCE_STYLES = {
    Confidence.HIGH: "green",
    Confidence.MEDIUM: "yellow",
    Confidence.LOW: "red",
    Confidence.UNVERIFIED: "bold white on red",
}


def _confidence_label(level: Confidence) -> str:
    style = _CONFIDENCE_STYLES.get(level, "")
    text = level.value[:4]
    return f"[{style}]{text}[/{style}]" if style else text


def _print_why(analyses: list[ImageAnalysis]) -> None:
    """State the case for the top pick, and what it costs.

    A ranked table answers "which one"; it never answers "why that one".
    Without this section the reader is asked to trust a number whose
    derivation is invisible -- which is exactly the failure mode this tool
    exists to avoid in other people's scanners.
    """
    if not analyses:
        return
    best = analyses[0]
    console.print(f"\n[bold]Why {safe(best.image.full_reference)}?[/bold]")
    for reason in best.why[:10]:
        console.print(f"  [green]+[/green] {safe(reason)}")
    if best.trade_offs:
        console.print("\n[bold]Trade-offs[/bold]")
        for cost in best.trade_offs[:10]:
            console.print(f"  [yellow]![/yellow] {safe(cost)}")

    _print_verdict(best)

    facts = best.facts
    console.print(
        f"\n[dim]Evidence: {facts.determined_count} fact(s) determined | "
        f"hardening coverage {best.hardening.coverage:.0%} | "
        f"scanner {safe(best.scan.scanner)}[/dim]"
    )
    if best.image.digest_known:
        console.print(
            f"[dim]Deploy this exact image: {best.pinned_reference}[/dim]", soft_wrap=True
        )


def _print_verdict(analysis: ImageAnalysis) -> None:
    """State the verdict and the evidence behind it, in that order.

    The failure this prevents is the one the whole project is organised
    around: a reader glancing at a table and reading an empty findings
    column as "clean". An image nobody could scan and an image with nothing
    wrong occupy the same row shape, so the difference is spelled out --
    the confidence level, what is missing, and whether the thing may go to
    production at all.
    """
    level = analysis.confidence
    style = _CONFIDENCE_STYLES.get(level, "")
    console.print(f"\n[{style}]{level.value}[/{style}]" if style else f"\n{level.value}")

    # At HIGH the reasons are what was verified; below it they are what is
    # missing. Same list, opposite meaning, so the heading says which.
    console.print(f"  [dim]{'Evidence:' if level is Confidence.HIGH else 'Evidence gaps:'}[/dim]")
    for reason in analysis.confidence_reasons:
        console.print(f"    - {safe(reason)}")

    if analysis.production_ready:
        console.print("  [green]Production ready[/green]")
        return
    console.print("  [red]Not production ready[/red]")
    for reason in analysis.readiness_reasons:
        console.print(f"    [red]x[/red] {safe(reason)}")


def _print_details(analyses: list[ImageAnalysis]) -> None:
    """Per-image registry link and the scan evidence backing its score.

    Both are listed below the table rather than in it: URLs and file paths
    are far too wide for a terminal column, and each image needs its *own*
    evidence path, not just a pointer to the aggregate manifest.
    """
    if not analyses:
        return
    console.print("\n[bold]Details[/bold]")
    for i, a in enumerate(analyses, 1):
        console.print(
            f"  {i}. [cyan]{safe(a.image.full_reference)}[/cyan]  [dim]{safe(a.image.source)}[/dim]"
        )
        if a.hub_url:
            # soft_wrap keeps the URL on one line so it stays copy-pasteable.
            console.print(f"     link:     [link={a.hub_url}]{a.hub_url}[/link]", soft_wrap=True)
        if a.evidence_paths:
            for scanner, path in sorted(a.evidence_paths.items()):
                note = _shared_scan_note(a, path)
                console.print(f"     {scanner + ':':9} [dim]{path}{note}[/dim]", soft_wrap=True)
        else:
            console.print("     [dim]evidence: not recorded[/dim]")


def _shared_scan_note(analysis: ImageAnalysis, path: str) -> str:
    """Flag evidence produced under a sibling tag's name.

    Tags that share a manifest digest are scanned once and share the
    result, so the file can be named for whichever tag triggered the scan.
    That is correct -- they are the same image -- but without saying so the
    path looks like it belongs to the wrong image.
    """
    if not path:
        return ""
    own_prefix = f"{slugify_reference(analysis.image.full_reference)}__"
    return "" if Path(path).name.startswith(own_prefix) else "  (shared digest)"


def _print_tier_warnings(analyses: list[ImageAnalysis]) -> None:
    """Surface tiers that oblige the reader to act.

    The advice comes from `SecurityTier`, so the terminal states the
    domain's rule rather than a copy of it that can drift.
    """
    flagged = [
        (a, SecurityTier.ADVICE.get(Tier(a.tier), ""))
        for a in analyses
        if not a.production_ready or Tier(a.tier) in SecurityTier.ADVICE
    ]
    flagged = [(a, advice) for a, advice in flagged if advice]
    if not flagged:
        return
    console.print("\n[bold yellow]! Requires review[/bold yellow]")
    for a, advice in flagged:
        console.print(f"  {safe(a.image.full_reference)}  [dim]Tier {safe(a.tier)}: {advice}[/dim]")


def _print_divergences(analyses: list[ImageAnalysis]) -> None:
    disputed = [a for a in analyses if a.scan_divergence]
    if not disputed:
        return
    console.print("\n[bold yellow]! Scanner divergence[/bold yellow]")
    for a in disputed:
        console.print(f"  {safe(a.image.full_reference)}: [dim]{safe(a.scan_divergence)}[/dim]")


def _print_unverified(result: AnalysisResult) -> None:
    """List the tags that could not be scanned, grouped by classified cause.

    Noventa e três linhas repetindo `ERROR: FATAL Fatal error run error: init
    error: DB error: error in v...` não é diagnóstico: é o mesmo prefixo
    cortado noventa e três vezes, sem nomear causa nenhuma. O resumo por
    causa em cima diz de imediato que se trata de *um* problema -- o banco de
    vulnerabilidades -- e não de noventa e três imagens ruins.
    """
    if not result.unverified:
        return
    console.print("\n[bold yellow]! Unverified (technical error)[/bold yellow]")
    console.print(
        "[dim]  These tags were never scored -- no successful scan, no recommendation.[/dim]"
    )

    by_kind = Counter(item.kind for item in result.unverified)
    console.print(
        "  [bold]Causes:[/bold] "
        + ", ".join(f"{kind} x{count}" for kind, count in by_kind.most_common())
    )

    for item in result.unverified[:10]:
        console.print(
            f"  {safe(item.image_reference)}  "
            f"[dim]{safe(item.kind)}: {safe(short_reason(item.reason))}[/dim]"
        )
    remaining = len(result.unverified) - 10
    if remaining > 0:
        console.print(f"  [dim]... and {remaining} more (see log file)[/dim]")
    console.print("  [dim]Run with --verbose for the full scanner output.[/dim]")


def _print_deferred(result: AnalysisResult) -> None:
    """As tags que a busca achou e o run não mediu, com o motivo.

    Existe pelo mesmo motivo que `_print_unverified`: uma tabela limpa não
    pode esconder o que ficou de fora. A diferença entre os dois blocos é
    a que importa -- lá estão scans que falharam, aqui estão scans que não
    foram tentados, e o segundo é uma escolha desta ferramenta, não um
    acidente. Por isso o bloco também diz como desfazê-la.
    """
    if not result.deferred:
        return

    console.print()
    console.print(
        Panel(
            f"[bold cyan]Not Measured ({result.deferred_count} of "
            f"{result.tags_discovered} tags found)[/bold cyan]",
            expand=False,
        )
    )
    console.print(
        "[dim]These tags exist and were not scanned. That is not a verdict on "
        "them: nothing here was measured, so nothing here is being claimed.[/dim]"
    )
    console.print()

    by_reason = Counter(item.reason.value for item in result.deferred)
    for reason, count in by_reason.most_common():
        console.print(f"  [cyan]{reason}[/cyan]  {count}")
    console.print()

    for item in result.deferred[:10]:
        console.print(f"  [dim]{safe(item.reference)}[/dim] -- {safe(item.detail)}")
    remaining = result.deferred_count - 10
    if remaining > 0:
        console.print(f"  [dim]... and {remaining} more (see --format json)[/dim]")

    console.print()
    console.print(
        "[dim]To measure every tag found: --budget 0, or set scan_budget = 0 "
        "in the config file.[/dim]"
    )


def _nothing_could_be_measured(result: AnalysisResult) -> bool:
    """True when tags were found but not one of them could be scanned.

    This is the difference between "we looked and nothing was good enough"
    and "we never managed to look". Both end with an empty table, and only
    the second is a technical failure.
    """
    return result.total_tags_analyzed == 0 and bool(result.unverified)


def _measurement_failure_message(result: AnalysisResult) -> str:
    """Lead with the cause rather than with a verdict about the images.

    `No suitable images found` on a machine with no scanner installed reads
    as a statement about the tags -- that they were examined and rejected.
    Nothing was examined. Naming the dominant cause up front turns the
    output into something the reader can act on.
    """
    causes = Counter(item.kind for item in result.unverified)
    dominant, count = causes.most_common(1)[0]
    hint = _CAUSE_HINTS.get(
        dominant, "Run with --verbose for the scanner output, or see the log file above."
    )
    return (
        f"[bold red]No image could be scanned.[/bold red]\n"
        f"[red]All {count} candidate(s) failed with: {dominant}[/red]\n\n"
        f"[bold]Suggested action[/bold]\n  {hint}\n\n"
        f"[dim]This is a technical failure, not a security verdict: "
        f"nothing was measured, so nothing can be said about these images.[/dim]"
    )


#: What to do about each classified failure cause, in the reader's terms.
_CAUSE_HINTS = {
    "SCANNER_MISSING": "Install Trivy or Grype, then re-run. `dockerls doctor` checks for both.",
    "DB_INIT_FAILED": (
        "The vulnerability database could not be prepared. Check network access to "
        "ghcr.io, then re-run."
    ),
    "TIMEOUT": (
        "Scans exceeded the timeout. Raise DOCKERLS_SCANNER_TIMEOUT, or lower --workers "
        "to reduce contention."
    ),
    "RATE_LIMITED": "Rate limited by the registry. Run `dockerls login`, or retry later.",
    "AUTH_REQUIRED": "The registry requires credentials. Run `dockerls login`.",
    "NOT_FOUND": "None of the discovered tags could be pulled. Check the image name.",
}


def _exit_code(result: AnalysisResult, fail_on: FailOn) -> int:
    items = result.recommendations or result.alternatives
    if items and fail_on != FailOn.NONE:
        counter = _FAIL_ON_COUNT[fail_on]
        if counter(items[0]) > 0:
            return EXIT_ERROR_CODE

    if result.baseline_met and result.recommendations:
        return EXIT_BASELINE_MET
    if result.alternatives:
        return EXIT_ALTERNATIVES_FOUND
    if result.total_tags_scanned == 0:
        return EXIT_ERROR_CODE
    # Tags were discovered but not one could be scanned. Code 3 is published
    # as "nothing usable was found" -- a statement about the *images*, which
    # a CI gate is entitled to act on. With no scanner installed, or a
    # vulnerability database that would not download, nothing was measured
    # at all, and reporting that as a verdict is exactly the substitution
    # this tool must never make. It is an operational failure: code 1.
    if _nothing_could_be_measured(result):
        return EXIT_ERROR_CODE
    return EXIT_NONE_FOUND
