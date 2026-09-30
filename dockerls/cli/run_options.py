"""The options every measuring command shares: platform, budget, profile, filters.

Parsed here, once, and reported through the shared usage-error path (exit 1):
Typer's own validation exits with 2, and 2 is a *verdict* in this CLI
(`recommend`: "alternatives found", `analyze --fail-on`: "the gate failed"),
so a typo in a flag must never be able to look like one. See `cli/options.py`.

Precedence, highest first, for anything a profile also sets:

    explicit flag  >  profile  >  configuration file / environment  >  built-in default

A profile is itself an explicit choice on the command line, so it overrides
ambient configuration; a specific flag overrides the profile.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import typer
from rich.console import Console

from dockerls.domain.value_objects.candidate_criteria import CandidateCriteria, InvalidCriteriaError
from dockerls.domain.value_objects.execution_profile import ExecutionProfile, resolve_profile
from dockerls.domain.value_objects.platform import InvalidPlatformError, Platform, parse_platform
from dockerls.exit_codes import EXIT_ERROR

_stderr = Console(stderr=True)

#: The longest budget accepted: a day. A budget that long is "no budget"; the
#: cap only refuses typos (`--time-budget 600000`).
MAX_TIME_BUDGET_SECONDS = 24 * 3600


@dataclass(frozen=True)
class RunOptions:
    platform: Platform
    time_budget: float | None = None
    profile: ExecutionProfile | None = None
    criteria: CandidateCriteria = field(default_factory=CandidateCriteria)
    #: True when `--platform` was given (as opposed to the default applying).
    platform_explicit: bool = False


def _fail(message: str) -> typer.Exit:
    _stderr.print(f"[red]Error:[/red] {message}")
    return typer.Exit(EXIT_ERROR)


def parse_time_budget(value: float | None) -> float | None:
    if value is None:
        return None
    if not math.isfinite(value) or value <= 0:
        raise _fail("--time-budget must be a positive number of seconds")
    if value > MAX_TIME_BUDGET_SECONDS:
        raise _fail(f"--time-budget above {MAX_TIME_BUDGET_SECONDS} seconds is not a budget")
    return float(value)


def parse_run_options(
    *,
    platform: str | None = None,
    time_budget: float | None = None,
    profile: str | None = None,
    runtime_version: str | None = None,
    distro: str | None = None,
    variant: str | None = None,
) -> RunOptions:
    """Validate the shared options, or exit 1 naming what is wrong."""
    try:
        chosen_platform = parse_platform(platform)
        chosen_profile = resolve_profile(profile)
        criteria = CandidateCriteria.build(
            # The platform filter is only *confirmed* when the listing
            # publishes architectures, and is otherwise settled by identity
            # resolution: it is passed only when asked for explicitly.
            platform=platform if platform and platform.strip() else None,
            runtime_version=runtime_version,
            distro=distro,
            variant=variant,
        )
    except (InvalidPlatformError, InvalidCriteriaError, ValueError) as e:
        raise _fail(str(e)) from e
    return RunOptions(
        platform=chosen_platform,
        time_budget=parse_time_budget(time_budget),
        profile=chosen_profile,
        criteria=criteria,
        platform_explicit=bool(platform and platform.strip()),
    )
