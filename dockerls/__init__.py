"""DockerLs: Enterprise Docker Image Security Advisor."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("dockerls")
except PackageNotFoundError:
    # Editable/dev checkout without an installed distribution record.
    __version__ = "0.0.0+dev"
