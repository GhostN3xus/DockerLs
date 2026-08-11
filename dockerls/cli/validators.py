"""Typer-facing adapters over the pure validators in ``dockerls.utils.validation``.

They exist so an out-of-range option produces a readable CLI error instead of
either a raw ``ValueError`` traceback or -- worse, in the case of
``--workers 0`` -- a scan loop that blocks forever on a semaphore nobody can
acquire.
"""

from __future__ import annotations

import typer

from dockerls.utils.validation import validate_threshold, validate_workers


def _hint(param: str) -> str:
    return "--" + param.replace("_", "-")


def check_threshold(value: int, param: str, *, minimum: int = 0) -> int:
    try:
        return validate_threshold(value, param, minimum=minimum)
    except ValueError as e:
        raise typer.BadParameter(str(e), param_hint=_hint(param)) from e


def check_limit(value: int, param: str = "limit") -> int:
    return check_threshold(value, param, minimum=1)


def check_workers(value: int, param: str = "workers") -> int:
    try:
        return validate_workers(value, param)
    except ValueError as e:
        raise typer.BadParameter(str(e), param_hint=_hint(param)) from e
