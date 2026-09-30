from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console

from dockerls.application.services.saved_run import UnusableRunError, result_from_document
from dockerls.cli.dependencies import build_recommend_use_case, build_run_store, resolve_tag_limit
from dockerls.cli.image_names import reject_tagged_reference
from dockerls.cli.progress import scan_status
from dockerls.cli.validators import check_limit, check_workers
from dockerls.exit_codes import EXIT_ERROR
from dockerls.exporters.factory import ExporterFactory
from dockerls.infrastructure.run_store import InvalidRunIdError
from dockerls.utils.validation import validate_output_path

console = Console()
diagnostics = Console(stderr=True)


def export(
    image: str | None = typer.Argument(
        None,
        help=(
            "Docker image name only, without a tag (e.g. 'node', not 'node:18'). "
            "Use 'analyze' or 'advisor' for a specific tag. Omit it with --run."
        ),
    ),
    output_format: str = typer.Option(
        "json", "--format", "-f", help="Export format: json, csv, html, markdown, sarif"
    ),
    output: str = typer.Option("", "--output", "-o", help="Output file path (default: stdout)"),
    workers: int | None = typer.Option(
        None, "--workers", "-w", help="Concurrent workers [config: workers, default 10]"
    ),
    limit: int | None = typer.Option(
        None, "--limit", "-l", help="Max tags to discover [config: max_tags, default 100]"
    ),
    run: str | None = typer.Option(
        None,
        "--run",
        help=(
            "Export a saved run by its id (printed by every run) instead of measuring again: "
            "nothing is scanned, resolved or enriched"
        ),
    ),
) -> None:
    """Export analysis results in various formats."""
    if run is not None:
        if image:
            diagnostics.print("[red]Error:[/red] give an image to measure, or --run, not both")
            raise typer.Exit(EXIT_ERROR)
        raise typer.Exit(_export_saved_run(run, output_format, output))
    if not image:
        diagnostics.print("[red]Error:[/red] give an image name to measure, or --run RUN_ID")
        raise typer.Exit(EXIT_ERROR)

    # `None` means "not given", so the configured value applies; only an
    # explicitly supplied value is range-checked here.
    if workers is not None:
        workers = check_workers(workers)
    if limit is not None:
        limit = check_limit(limit)
    error = reject_tagged_reference(image, "export")
    if error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(EXIT_ERROR)
    try:
        asyncio.run(_export(image, output_format, output, workers, limit))
    except ValueError as e:
        console.print(f"[red]Invalid configuration:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e


def _export_saved_run(run_id: str, fmt: str, output: str) -> int:
    """Re-render a saved run. Returns the process exit code.

    The identifier is the only thing taken from the user to find the file: it
    has to look like a run id, and is joined to the store's own directory, so
    it cannot name any other path.
    """
    try:
        exporter = ExporterFactory.create(fmt)
    except ValueError as e:
        diagnostics.print(f"[red]{e}[/red]")
        return EXIT_ERROR
    try:
        document = build_run_store().load(run_id)
    except InvalidRunIdError as e:
        diagnostics.print(f"[red]Error:[/red] {e}")
        return EXIT_ERROR
    if document is None:
        diagnostics.print(
            f"[red]Error:[/red] no saved run {run_id!r} (it may have been pruned, or never saved)"
        )
        return EXIT_ERROR
    try:
        result = result_from_document(document)
    except UnusableRunError as e:
        diagnostics.print(f"[red]Error:[/red] run {run_id}: {e}")
        return EXIT_ERROR

    payload = exporter.export_string(result)
    if fmt.lower() == "json":
        payload = _with_run_metadata(payload, document)

    if not output:
        # soft_wrap avoids Rich reflowing/inserting newlines into
        # machine-readable output (JSON, CSV, SARIF).
        console.print(payload, soft_wrap=True)
        return 0
    try:
        path = validate_output_path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
    except (OSError, ValueError) as e:
        diagnostics.print(f"[red]Could not write {output}:[/red] {e}")
        return EXIT_ERROR
    console.print(f"[green]Run {run_id} exported to {path}[/green]")
    return 0


def _with_run_metadata(payload: str, document: dict[str, object]) -> str:
    """Say, inside the JSON itself, that this came from a saved run and which."""
    try:
        parsed = json.loads(payload)
    except ValueError:
        return payload
    if not isinstance(parsed, dict):
        return payload
    parsed["saved_run"] = {
        "run_id": document.get("run_id"),
        "created_at": document.get("created_at"),
        "command": document.get("command"),
        "dockerls_version": document.get("dockerls_version"),
        "platform": document.get("platform"),
        "completeness": document.get("completeness"),
        "rescanned": False,
    }
    return json.dumps(parsed, indent=2, ensure_ascii=False, default=str)


async def _export(
    image: str, fmt: str, output: str, workers: int | None, limit: int | None
) -> None:
    # Same fallback as `recommend`: omitting a flag means "use the
    # configured value", rather than a hard-coded default shadowing it.
    use_case = await build_recommend_use_case(workers=workers)
    with scan_status(f"Scanning {image}..."):
        result = await use_case.execute(image, limit=resolve_tag_limit(limit))

    try:
        exporter = ExporterFactory.create(fmt)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(EXIT_ERROR) from e

    if output:
        try:
            path = validate_output_path(output)
            path.parent.mkdir(parents=True, exist_ok=True)
            exporter.export(result, path)
        except (OSError, ValueError) as e:
            # An unwritable or suspicious destination is user error, not a crash.
            console.print(f"[red]Could not write {Path(output)}:[/red] {e}")
            raise typer.Exit(EXIT_ERROR) from e
        console.print(f"[green]Report exported to {path}[/green]")
    else:
        # soft_wrap avoids Rich reflowing/inserting newlines into
        # machine-readable output (JSON, CSV, SARIF).
        console.print(exporter.export_string(result), soft_wrap=True)
