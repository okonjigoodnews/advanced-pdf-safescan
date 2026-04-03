"""Environment-aware runtime configuration for API and hosted deployments."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from src.utils.paths import data_dir as configured_data_dir
from src.utils.paths import model_dir as configured_model_dir

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8008
DEFAULT_DASHBOARD_PUBLIC_URL = "http://127.0.0.1:8501"
DEFAULT_RECENT_LIMIT = 12
DEFAULT_CORS_ALLOWED_ORIGINS = ("*",)
DEFAULT_SERVICE_NAME = "Advanced PDFSafeScan API"
API_TOKEN_HEADER_NAME = "X-API-Token"


@dataclass(frozen=True, slots=True)
class APIRuntimeConfig:
    """Immutable runtime configuration shared by local and hosted API modes."""

    host: str
    port: int
    public_base_url: str
    dashboard_public_url: str
    model_dir: Path
    data_dir: Path
    cors_allowed_origins: tuple[str, ...]
    api_auth_token: str
    recent_limit: int = DEFAULT_RECENT_LIMIT
    service_name: str = DEFAULT_SERVICE_NAME

    @property
    def history_path(self) -> Path:
        """Return the persistent scan history JSON path."""
        return self.data_dir / "history" / "scan_history.json"

    @property
    def review_notes_path(self) -> Path:
        """Return the persistent analyst review JSON path."""
        return self.data_dir / "history" / "analyst_reviews.json"

    @property
    def is_local_development(self) -> bool:
        """Return True when the public API base still points to a loopback address."""
        return _is_loopback_url(self.public_base_url)


def build_runtime_config(
    *,
    host: str | None = None,
    port: int | str | None = None,
    public_base_url: str | None = None,
    dashboard_public_url: str | None = None,
    model_dir: str | Path | None = None,
    data_dir: str | Path | None = None,
    cors_allowed_origins: str | Iterable[str] | None = None,
    api_auth_token: str | None = None,
    recent_limit: int | str | None = None,
) -> APIRuntimeConfig:
    """Build runtime configuration from explicit values and environment variables."""
    resolved_host = str(host or os.getenv("APP_HOST") or DEFAULT_HOST).strip()
    resolved_port = _safe_int(port if port is not None else os.getenv("APP_PORT"), DEFAULT_PORT)
    resolved_public_base_url = _normalize_base_url(
        public_base_url
        or os.getenv("APP_PUBLIC_BASE_URL")
        or _build_default_public_base_url(resolved_host, resolved_port)
    )
    resolved_dashboard_public_url = _normalize_base_url(
        dashboard_public_url
        or os.getenv("DASHBOARD_PUBLIC_URL")
        or DEFAULT_DASHBOARD_PUBLIC_URL
    )
    resolved_model_dir = configured_model_dir(model_dir)
    resolved_data_dir = configured_data_dir(data_dir)
    resolved_cors_allowed_origins = _parse_allowed_origins(
        cors_allowed_origins if cors_allowed_origins is not None else os.getenv("CORS_ALLOWED_ORIGINS"),
        public_base_url=resolved_public_base_url,
        dashboard_public_url=resolved_dashboard_public_url,
    )
    resolved_api_auth_token = str(api_auth_token if api_auth_token is not None else os.getenv("API_AUTH_TOKEN", "")).strip()
    resolved_recent_limit = _safe_int(
        recent_limit if recent_limit is not None else os.getenv("RECENT_SCAN_LIMIT"),
        DEFAULT_RECENT_LIMIT,
    )

    return APIRuntimeConfig(
        host=resolved_host,
        port=resolved_port,
        public_base_url=resolved_public_base_url,
        dashboard_public_url=resolved_dashboard_public_url,
        model_dir=resolved_model_dir,
        data_dir=resolved_data_dir,
        cors_allowed_origins=resolved_cors_allowed_origins,
        api_auth_token=resolved_api_auth_token,
        recent_limit=max(resolved_recent_limit, 1),
    )


def _parse_allowed_origins(
    value: str | Iterable[str] | None,
    *,
    public_base_url: str,
    dashboard_public_url: str,
) -> tuple[str, ...]:
    """Normalize configured CORS origins from env vars or explicit values."""
    if value is None:
        if _is_loopback_url(public_base_url):
            return DEFAULT_CORS_ALLOWED_ORIGINS
        return (dashboard_public_url,)

    if isinstance(value, str):
        items = [item.strip() for item in value.split(",")]
    else:
        items = [str(item).strip() for item in value]

    normalized_items = tuple(item for item in items if item)
    return normalized_items or DEFAULT_CORS_ALLOWED_ORIGINS


def _build_default_public_base_url(host: str, port: int) -> str:
    """Build a sensible API base URL when one is not configured explicitly."""
    return f"http://{host}:{port}"


def _normalize_base_url(url: str) -> str:
    """Normalize a configured base URL without a trailing slash."""
    return str(url).strip().rstrip("/")


def _is_loopback_url(url: str) -> bool:
    """Return True when a URL points to a local-only host."""
    hostname = (urlparse(url).hostname or "").strip().casefold()
    return hostname in {"127.0.0.1", "localhost", "0.0.0.0"}


def _safe_int(value: int | str | None, default: int) -> int:
    """Convert a configuration value to int safely."""
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default
