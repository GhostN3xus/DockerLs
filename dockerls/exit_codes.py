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
