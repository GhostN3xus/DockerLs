"""Turn a saved run document back into the result it was, without measuring.

`dockerls export --run <id>` re-renders an earlier result in another format.
Nothing here scans, resolves or enriches: the document already carries the
measured identity, the evidence paths and the provenance, and they come out
exactly as they went in.

The document is data read from disk, so it is validated like any other
untrusted input: a shape the models do not accept is an error naming the run,
never a half-populated result presented as if it were complete.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis


class UnusableRunError(ValueError):
    """The saved document cannot be turned back into a result."""


def result_from_document(document: dict[str, Any]) -> AnalysisResult:
    payload = document.get("result")
    if not isinstance(payload, dict):
        raise UnusableRunError("the saved run carries no result")
    try:
        if document.get("command") == "analyze":
            analysis = ImageAnalysis.model_validate(payload)
            return AnalysisResult(
                query=analysis.image.requested_reference or analysis.image.full_reference,
                total_tags_scanned=1,
                total_tags_analyzed=1 if analysis.scan.is_verified else 0,
                baseline_met=analysis.production_ready,
                recommendations=[analysis] if analysis.scan.is_verified else [],
                completeness=analysis.completeness,
                pending_checks=analysis.pending_checks,
                platform=analysis.image.platform,
            )
        return AnalysisResult.model_validate(payload)
    except ValidationError as e:
        raise UnusableRunError(
            f"the saved run does not match the current result schema ({e.error_count()} problem(s))"
        ) from e
