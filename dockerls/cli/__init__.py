"""Command line interface.

`STARTED_AT` is taken the moment this package is first imported -- the earliest
point the process controls -- so a command can report how long it took to get
from there to running (`startup_seconds`). Interpreter start-up before this
line is not included, and the docs say so.
"""

import time

STARTED_AT = time.monotonic()


def startup_seconds() -> float:
    """Seconds from importing the CLI package until now."""
    return time.monotonic() - STARTED_AT
