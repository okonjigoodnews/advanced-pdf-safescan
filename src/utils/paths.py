"""Path helpers used across the project."""

from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    """Return the repository root directory."""
    return Path(__file__).resolve().parents[2]


def data_dir(path_override: str | Path | None = None) -> Path:
    """Return the configured data directory for persistent app state."""
    return _resolve_configured_path(
        path_override if path_override is not None else os.getenv("DATA_DIR"),
        default_relative="data",
    )


def model_dir(path_override: str | Path | None = None) -> Path:
    """Return the configured model directory for trained artifacts."""
    return _resolve_configured_path(
        path_override if path_override is not None else os.getenv("MODEL_DIR"),
        default_relative="models",
    )


def _resolve_configured_path(value: str | Path | None, *, default_relative: str) -> Path:
    """Resolve an optional absolute or project-relative configuration path."""
    if value in (None, ""):
        return project_root() / default_relative

    path = Path(value)
    if path.is_absolute():
        return path
    return project_root() / path
