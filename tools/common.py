"""Shared helpers for all multitool modules."""
import os
from pathlib import Path


class ToolError(Exception):
    """A user-facing error: printed as `error: ...` without a traceback."""


def data_dir(*parts):
    """Per-user state directory (override with $MULTITOOL_HOME)."""
    base = Path(os.environ.get("MULTITOOL_HOME", Path.home() / ".multitool"))
    path = base.joinpath(*parts)
    path.mkdir(parents=True, exist_ok=True)
    return path
