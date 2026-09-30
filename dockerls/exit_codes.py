"""The exit code contract every DockerLs command honours.

A pipeline can only branch on these numbers, so they are defined once here
instead of appearing as integer literals scattered through the CLI. The same
table is documented in the README under "Exit codes".
"""

from __future__ import annotations

from typing import Final

# The command ran and nothing violated a policy.
EXIT_OK: Final[int] = 0

# The command could not run to completion: a missing dependency, a network
# failure, a Dockerfile that does not exist, a failing `docker build`.
# Nothing was measured, so the result says nothing about security.
EXIT_ERROR: Final[int] = 1

# The command ran fine and the result violates a policy: a validation check
# failed (`errors > 0`), or `--fail-on` was triggered. This is the code a
# pipeline gate should treat as "the image is not allowed through".
EXIT_POLICY: Final[int] = 2


# --- Time budget and interruption ------------------------------------------
#
# Only ever returned by a run that was given `--time-budget` (or interrupted).
# A run without a budget keeps every exit code it had before.

# The time budget ended before a single measurement completed. Nothing was
# measured, so this says nothing about the images -- and it is not "1" on
# purpose: an operator can raise the budget and try again, which is not true of
# a missing scanner.
EXIT_TIME_BUDGET_EXHAUSTED: Final[int] = 4

# The time budget ended with some measurements done. What was measured is
# real and is shown, but the run is not a complete one and must not be read as
# an audit: a pipeline that wants to accept partial results has to say so by
# handling this code explicitly. A policy violation already *proven* by the
# measurements that did finish still exits with its own code (the violation
# needs no more evidence), and a partial run is never exit 0.
EXIT_PARTIAL_RESULT: Final[int] = 5

# The user cancelled (Ctrl-C). The POSIX convention for "terminated by SIGINT".
EXIT_INTERRUPTED: Final[int] = 130


def exit_code_for_completeness(code: int, completeness: str, *, violation: bool = False) -> int:
    """Fold a run's completeness into the exit code it would otherwise return.

    * `COMPLETE` -- `code` unchanged: nothing about the budget applies.
    * a violation already proven by what was measured -- `code` unchanged
      (a partial result cannot *soften* a failure, only fail to prove a pass).
    * an operational error (`EXIT_ERROR`) -- unchanged.
    * `PARTIAL` -- `EXIT_PARTIAL_RESULT`, whatever `code` was (a partial run
      never exits 0, and never claims "alternatives found" as if it were done).
    * `NO_RESULT` -- `EXIT_TIME_BUDGET_EXHAUSTED`.
    """
    if completeness == "COMPLETE" or violation or code == EXIT_ERROR:
        return code
    if completeness == "NO_RESULT":
        return EXIT_TIME_BUDGET_EXHAUSTED
    return EXIT_PARTIAL_RESULT
