"""Hosted-ready Flask API bridge for Advanced PDFSafeScan."""

from __future__ import annotations

import argparse
import base64
import logging
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from flask import Flask, jsonify, request
except ImportError:  # pragma: no cover - depends on local environment
    Flask = None
    jsonify = None
    request = None

try:
    from werkzeug.exceptions import RequestEntityTooLarge
except ImportError:  # pragma: no cover - depends on local environment
    RequestEntityTooLarge = Exception

from app.main import run_pdf_analysis_details
from app.runtime_config import (
    API_TOKEN_HEADER_NAME,
    APIRuntimeConfig,
    build_runtime_config,
)
from src.ml.classifier import MLClassifierError, MalwareClassifier, load_saved_model
from src.parser.document_parser import PDFParserError
from src.reporting.extension_bridge import (
    build_recent_scan_rows,
    build_scan_response_from_analysis,
    build_scan_response_from_history_record,
    find_cached_history_record_by_sha256,
)
from src.reporting.forensics import compute_sha256, recommendation_for_verdict
from src.reporting.history import append_scan_history_records, load_scan_history
from src.reporting.review_notes import load_analyst_reviews_by_sha256

DEFAULT_DOWNLOAD_TIMEOUT_SECONDS = 20
UPLOAD_FIELD_NAME = "file"
_USER_AGENT = "AdvancedPDFSafeScan-HostedAPI/3.0"
_PROTECTED_API_PATHS = frozenset(("/api/scan/recent", "/api/scan/file", "/api/scan/url"))
_MAX_UPLOAD_BYTES = 15 * 1024 * 1024
_MAX_JSON_REQUEST_BYTES = 22 * 1024 * 1024
_MAX_SOURCE_URL_LENGTH = 2048
_ALLOWED_REMOTE_SCHEMES = {"http", "https"}
CLIENT_ID_HEADER_NAME = "X-Client-ID"

_classifier_cache: dict[str, MalwareClassifier] = {}
_logger = logging.getLogger(__name__)


def create_app(
    config: APIRuntimeConfig | None = None,
    **overrides: Any,
) -> Any:
    """Create the Flask application for local or hosted deployment."""
    if Flask is None or jsonify is None or request is None:
        raise RuntimeError(
            "Flask is required to run the API server. Install it with 'pip install flask waitress'."
        )

    runtime_config = config or build_runtime_config(**overrides)
    app = Flask(__name__)
    app.config["RUNTIME_CONFIG"] = runtime_config
    app.config["MAX_CONTENT_LENGTH"] = _MAX_JSON_REQUEST_BYTES

    @app.before_request
    def enforce_request_policy() -> Any:
        """Apply origin checks and optional token auth before protected endpoints run."""
        if not str(request.path).startswith("/api/"):
            return None

        origin = str(request.headers.get("Origin", "")).strip()
        if not _is_origin_allowed(origin, runtime_config):
            return _json_error(
                "Request origin is not allowed for this deployment.",
                status_code=403,
                error_code="origin_not_allowed",
                runtime_config=runtime_config,
            )

        if request.method == "OPTIONS":
            return None

        if request.path in _PROTECTED_API_PATHS and runtime_config.api_auth_token:
            if not _has_valid_api_token(runtime_config.api_auth_token):
                return _json_error(
                    "Valid API authentication is required for this endpoint.",
                    status_code=401,
                    error_code="unauthorized",
                    runtime_config=runtime_config,
                )
        return None

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_entity_too_large(exc: Exception) -> Any:
        """Return a JSON 413 response for oversized requests."""
        _logger.warning("Rejected oversized request to %s", request.path)
        return _json_error(
            f"Request body exceeds the maximum supported size of {_MAX_UPLOAD_BYTES} bytes.",
            status_code=413,
            error_code="request_too_large",
            runtime_config=runtime_config,
        )

    @app.after_request
    def add_cors_headers(response: Any) -> Any:
        """Apply deployment-aware CORS headers for extension and browser clients."""
        origin = str(request.headers.get("Origin", "")).strip()
        allow_origin = _allowed_response_origin(origin, runtime_config)
        if allow_origin:
            response.headers["Access-Control-Allow-Origin"] = allow_origin
            if allow_origin != "*":
                response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-API-Token, X-Client-ID"
        )
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Max-Age"] = "3600"
        return response

    # BUG 1 FIXED: index() is now correctly dedented outside add_cors_headers
    @app.route("/", methods=["GET"])
    def index():
        return jsonify({
            "status": "ok",
            "message": "Advanced PDFSafeScan backend is running",
            "dashboard_url": runtime_config.dashboard_public_url
        })

    # BUG 2 FIXED: Removed duplicate health() definition, keeping only this one with docstring
    @app.route("/api/health", methods=["GET"], provide_automatic_options=False)
    def health() -> Any:
        """Return a simple deployment-aware health payload."""
        return jsonify(
            {
                "status": "ok",
                "service": runtime_config.service_name,
                "timestamp": _utc_timestamp(),
                "mode": "local-development" if runtime_config.is_local_development else "hosted",
                "public_base_url": runtime_config.public_base_url,
                "dashboard_url": runtime_config.dashboard_public_url,
                "authentication_required": bool(runtime_config.api_auth_token),
            }
        )

    @app.route("/api/scan/recent", methods=["GET"], provide_automatic_options=False)
    def recent_scans() -> Any:
        """Return recent scan rows for the extension popup and other clients."""
        limit = _safe_int(request.args.get("limit", runtime_config.recent_limit), runtime_config.recent_limit)
        history_records = _filter_history_records_for_client(
            load_scan_history(history_path=runtime_config.history_path),
            _request_client_id(),
        )
        review_records_by_sha256 = load_analyst_reviews_by_sha256(
            review_notes_path=runtime_config.review_notes_path
        )
        return jsonify(
            {
                "status": "ok",
                "items": build_recent_scan_rows(
                    history_records,
                    review_records_by_sha256,
                    limit=max(limit, 0),
                ),
                "dashboard_url": runtime_config.dashboard_public_url,
                "public_base_url": runtime_config.public_base_url,
            }
        )

    @app.route("/api/scan/file", methods=["POST"], provide_automatic_options=False)
    def scan_file() -> Any:
        """Accept an uploaded PDF file and return an extension-friendly scan response."""
        try:
            client_id = _request_client_id()
            file_name, content_type, pdf_bytes = _read_uploaded_pdf_request()
            _validate_pdf_upload(
                file_name=file_name,
                content_type=content_type,
                pdf_bytes=pdf_bytes,
            )
            payload = _scan_pdf_bytes(
                pdf_bytes=pdf_bytes,
                file_name=file_name,
                model_dir=runtime_config.model_dir,
                client_id=client_id,
                history_path=runtime_config.history_path,
                review_notes_path=runtime_config.review_notes_path,
            )
            payload["dashboard_url"] = runtime_config.dashboard_public_url
            payload["public_base_url"] = runtime_config.public_base_url
            return jsonify(payload)
        except APIRequestError as exc:
            return _json_error(
                exc.message,
                status_code=exc.status_code,
                error_code=exc.error_code,
                runtime_config=runtime_config,
            )
        except (FileNotFoundError, PDFParserError, MLClassifierError, ValueError) as exc:
            return _json_error(
                str(exc),
                status_code=500,
                error_code="scan_failure",
                runtime_config=runtime_config,
            )

    @app.route("/api/scan/url", methods=["POST"], provide_automatic_options=False)
    def scan_url() -> Any:
        """Accept a PDF URL, fetch it on the server, and return a scan response."""
        try:
            client_id = _request_client_id()
            request_payload = request.get_json(silent=True)
            if not isinstance(request_payload, dict):
                raise APIRequestError(
                    "Request body must be a JSON object containing a PDF URL.",
                    status_code=400,
                    error_code="invalid_request",
                )
            source_url = str(request_payload.get("url", "")).strip()
            if not source_url:
                raise APIRequestError(
                    "A PDF URL is required.",
                    status_code=400,
                    error_code="missing_url",
                )
            _validate_source_url(source_url)
            payload = _scan_pdf_url(
                source_url,
                model_dir=runtime_config.model_dir,
                client_id=client_id,
                history_path=runtime_config.history_path,
                review_notes_path=runtime_config.review_notes_path,
            )
            payload["dashboard_url"] = runtime_config.dashboard_public_url
            payload["public_base_url"] = runtime_config.public_base_url
            return jsonify(payload)
        except APIRequestError as exc:
            return _json_error(
                exc.message,
                status_code=exc.status_code,
                error_code=exc.error_code,
                runtime_config=runtime_config,
            )
        except urllib.error.URLError as exc:
            return _json_error(
                f"Failed to fetch PDF URL: {exc}",
                status_code=502,
                error_code="url_fetch_failed",
                runtime_config=runtime_config,
            )
        except (FileNotFoundError, PDFParserError, MLClassifierError, ValueError) as exc:
            _logger.exception("Unhandled API scan/url failure")
            return _json_error(
                "The API could not complete the requested scan.",
                status_code=500,
                error_code="scan_failure",
                runtime_config=runtime_config,
            )

    @app.route("/api/health", methods=["OPTIONS"])
    @app.route("/api/scan/recent", methods=["OPTIONS"])
    @app.route("/api/scan/file", methods=["OPTIONS"])
    @app.route("/api/scan/url", methods=["OPTIONS"])
    def options() -> Any:
        """Return a preflight response with deployment-aware CORS headers."""
        return ("", 204)

    return app


class APIRequestError(Exception):
    """Represent a clean, extension-friendly request validation error."""

    def __init__(self, message: str, *, status_code: int, error_code: str) -> None:
        """Store message and transport metadata for API responses."""
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code


def main(argv: list[str] | None = None) -> int:
    """Run the API server in local development mode."""
    parser = argparse.ArgumentParser(description="Run the Advanced PDFSafeScan API server.")
    parser.add_argument("--host", help="Host to bind the API server to. Overrides APP_HOST.")
    parser.add_argument("--port", type=int, help="Port to bind the API server to. Overrides APP_PORT.")
    parser.add_argument("--public-base-url", help="Public API base URL. Overrides APP_PUBLIC_BASE_URL.")
    parser.add_argument("--dashboard-url", help="Public Streamlit dashboard URL. Overrides DASHBOARD_PUBLIC_URL.")
    parser.add_argument("--model-dir", type=Path, help="Model directory. Overrides MODEL_DIR.")
    parser.add_argument("--data-dir", type=Path, help="Data directory. Overrides DATA_DIR.")
    parser.add_argument("--cors-allowed-origins", help="Comma-separated allowed CORS origins. Overrides CORS_ALLOWED_ORIGINS.")
    parser.add_argument("--api-auth-token", help="Optional shared API token. Overrides API_AUTH_TOKEN.")
    args = parser.parse_args(argv)

    runtime_config = build_runtime_config(
        host=args.host,
        port=args.port,
        public_base_url=args.public_base_url,
        dashboard_public_url=args.dashboard_url,
        model_dir=args.model_dir,
        data_dir=args.data_dir,
        cors_allowed_origins=args.cors_allowed_origins,
        api_auth_token=args.api_auth_token,
    )
    app = create_app(config=runtime_config)

    print(f"{runtime_config.service_name} running on http://{runtime_config.host}:{runtime_config.port}")
    print(f"Public base URL: {runtime_config.public_base_url}")
    print(f"Dashboard URL: {runtime_config.dashboard_public_url}")
    if runtime_config.api_auth_token:
        print(f"API token auth: enabled via header '{API_TOKEN_HEADER_NAME}'")
    else:
        print("API token auth: disabled")
    print("For hosted deployment, serve 'wsgi:app' with waitress or another production WSGI server.")

    app.run(host=runtime_config.host, port=runtime_config.port, debug=False)
    return 0


def _json_error(
    message: str,
    *,
    status_code: int,
    error_code: str,
    runtime_config: APIRuntimeConfig | None = None,
) -> Any:
    """Return a consistent JSON error payload."""
    payload = {
        "status": "error",
        "error_code": error_code,
        "message": message,
        "timestamp": _utc_timestamp(),
    }
    if runtime_config is not None:
        payload["dashboard_url"] = runtime_config.dashboard_public_url
        payload["public_base_url"] = runtime_config.public_base_url
    return jsonify(payload), status_code


def _read_uploaded_pdf_request() -> tuple[str, str, bytes]:
    """Read a PDF upload from multipart form-data or JSON base64 payload."""
    if request.files and UPLOAD_FIELD_NAME in request.files:
        uploaded_file = request.files[UPLOAD_FIELD_NAME]
        file_name = str(uploaded_file.filename or "uploaded.pdf")
        pdf_bytes = uploaded_file.read()
        if len(pdf_bytes) > _MAX_UPLOAD_BYTES:
            raise APIRequestError(
                f"Uploaded file exceeds the maximum supported size of {_MAX_UPLOAD_BYTES} bytes.",
                status_code=413,
                error_code="request_too_large",
            )
        return file_name, str(uploaded_file.mimetype or ""), pdf_bytes

    request_payload = request.get_json(silent=True)
    if not isinstance(request_payload, dict):
        raise APIRequestError(
            "Provide a multipart file upload or a JSON base64 payload.",
            status_code=400,
            error_code="missing_file",
        )

    encoded_bytes = str(request_payload.get("file_bytes_base64", "")).strip()
    if not encoded_bytes:
        raise APIRequestError(
            "Missing uploaded file. Use the 'file' form field or provide file_bytes_base64.",
            status_code=400,
            error_code="missing_file",
        )
    try:
        pdf_bytes = base64.b64decode(encoded_bytes)
    except (ValueError, TypeError) as exc:
        raise APIRequestError(
            f"Invalid base64 file payload: {exc}",
            status_code=400,
            error_code="invalid_file_payload",
        ) from exc
    if len(pdf_bytes) > _MAX_UPLOAD_BYTES:
        raise APIRequestError(
            f"Uploaded file exceeds the maximum supported size of {_MAX_UPLOAD_BYTES} bytes.",
            status_code=413,
            error_code="request_too_large",
        )

    return (
        str(request_payload.get("file_name", "uploaded.pdf")),
        str(request_payload.get("content_type", "")),
        pdf_bytes,
    )


def _validate_pdf_upload(*, file_name: str, content_type: str, pdf_bytes: bytes) -> None:
    """Validate that the uploaded payload looks like a PDF before scanning."""
    if not pdf_bytes:
        raise APIRequestError(
            "Uploaded file is empty.",
            status_code=400,
            error_code="empty_file",
        )
    if not _looks_like_pdf(file_name=file_name, content_type=content_type, pdf_bytes=pdf_bytes):
        raise APIRequestError(
            "Unsupported content type. Only PDF uploads are supported.",
            status_code=415,
            error_code="unsupported_content_type",
        )


def _validate_source_url(source_url: str) -> None:
    """Validate a remote PDF URL before the server attempts to fetch it."""
    if len(source_url) > _MAX_SOURCE_URL_LENGTH:
        raise APIRequestError(
            f"Source URL exceeds the maximum supported length of {_MAX_SOURCE_URL_LENGTH} characters.",
            status_code=400,
            error_code="invalid_url",
        )

    parsed_url = urllib.parse.urlparse(source_url)
    if parsed_url.scheme not in _ALLOWED_REMOTE_SCHEMES or not parsed_url.netloc:
        raise APIRequestError(
            "Only absolute http:// or https:// PDF URLs are supported.",
            status_code=400,
            error_code="invalid_url",
        )


def _scan_pdf_url(
    source_url: str,
    *,
    model_dir: Path,
    client_id: str = "",
    history_path: str | Path | None = None,
    review_notes_path: str | Path | None = None,
) -> dict[str, Any]:
    """Fetch a PDF URL and scan it through the existing backend pipeline."""
    file_name = _filename_from_url(source_url)
    request_object = urllib.request.Request(source_url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(request_object, timeout=DEFAULT_DOWNLOAD_TIMEOUT_SECONDS) as response:
            pdf_bytes = response.read()
            content_type = str(response.headers.get("Content-Type", "")).lower()
    except urllib.error.HTTPError as exc:
        _logger.warning("Remote PDF fetch failed with HTTP %s", exc.code)
        raise APIRequestError(
            f"Failed to fetch PDF URL: HTTP {exc.code}",
            status_code=502,
            error_code="url_fetch_failed",
        ) from exc
    except urllib.error.URLError as exc:
        _logger.warning("Remote PDF fetch failed: %s", exc.reason)
        raise APIRequestError(
            f"Failed to fetch PDF URL: {exc.reason}",
            status_code=502,
            error_code="url_fetch_failed",
        ) from exc

    if not pdf_bytes:
        raise APIRequestError(
            "The URL did not return any file content.",
            status_code=400,
            error_code="empty_response",
        )
    if len(pdf_bytes) > _MAX_UPLOAD_BYTES:
        raise APIRequestError(
            f"Fetched PDF exceeds the maximum supported size of {_MAX_UPLOAD_BYTES} bytes.",
            status_code=413,
            error_code="request_too_large",
        )
    if not _looks_like_pdf(file_name=file_name, content_type=content_type, pdf_bytes=pdf_bytes):
        raise APIRequestError(
            "The fetched URL did not return PDF content.",
            status_code=415,
            error_code="unsupported_content_type",
        )

    return _scan_pdf_bytes(
        pdf_bytes=pdf_bytes,
        file_name=file_name,
        model_dir=model_dir,
        source_url=source_url,
        client_id=client_id,
        history_path=history_path,
        review_notes_path=review_notes_path,
    )


def _scan_pdf_bytes(
    *,
    pdf_bytes: bytes,
    file_name: str,
    model_dir: Path,
    source_url: str = "",
    client_id: str = "",
    history_path: str | Path | None = None,
    review_notes_path: str | Path | None = None,
) -> dict[str, Any]:
    """Scan PDF bytes and return an extension-friendly JSON response."""
    sha256 = compute_sha256(pdf_bytes)
    history_records = load_scan_history(history_path=history_path)
    review_records_by_sha256 = load_analyst_reviews_by_sha256(review_notes_path=review_notes_path)
    cached_history_record = find_cached_history_record_by_sha256(history_records, sha256)
    cached_review_record = review_records_by_sha256.get(sha256)
    if cached_history_record is not None:
        cached_analysis_result = _build_cached_history_analysis_result(
            cached_history_record,
            file_name=file_name,
            client_id=client_id,
        )
        append_scan_history_records(
            [("extension_api_cached", cached_analysis_result)],
            history_path=history_path,
        )
        # BUG 3 FIXED: Pass client_id so the response is scoped to the correct client
        return build_scan_response_from_history_record(
            cached_history_record,
            source_url=source_url,
            cached=True,
            review_record=cached_review_record,
            client_id=client_id,
        )

    classifier = _get_classifier(model_dir=model_dir)
    temp_pdf_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_file:
            temp_file.write(pdf_bytes)
            temp_pdf_path = Path(temp_file.name)

        result = run_pdf_analysis_details(temp_pdf_path, classifier, sha256=sha256)
        summary = result["summary"]
        virustotal_result = result.get("virustotal", {})
        analysis_result = {
            "summary": {
                **summary,
                "file_name": file_name,
            },
            "sha256": sha256,
            "client_id": client_id,
            "recommendation": recommendation_for_verdict(str(summary.get("final_label", "unknown"))),
            "report_timestamp": _utc_timestamp(),
            "virustotal": virustotal_result,
        }
        append_scan_history_records(
            [("extension_api", analysis_result)],
            history_path=history_path,
        )
        scan_response = build_scan_response_from_analysis(
            analysis_result,
            source_url=source_url,
            cached=False,
            review_record=review_records_by_sha256.get(sha256),
        )
        scan_response["virustotal"] = virustotal_result
        return scan_response
    finally:
        if temp_pdf_path is not None and temp_pdf_path.exists():
            temp_pdf_path.unlink(missing_ok=True)


def _get_classifier(*, model_dir: Path) -> MalwareClassifier:
    """Load and cache the trained classifier for API scans."""
    cache_key = str(Path(model_dir).resolve())
    if cache_key not in _classifier_cache:
        _classifier_cache[cache_key] = load_saved_model(model_dir=model_dir)
    return _classifier_cache[cache_key]


def _request_client_id() -> str:
    """Return the normalized installation-scoped client id from the request."""
    return str(request.headers.get(CLIENT_ID_HEADER_NAME, "")).strip()


def _filter_history_records_for_client(
    history_records: list[dict[str, Any]],
    client_id: str,
) -> list[dict[str, Any]]:
    """Return only records visible to the requesting client installation."""
    normalized_client_id = str(client_id).strip()
    if normalized_client_id:
        return [
            record
            for record in history_records
            if str(record.get("client_id", "")).strip() == normalized_client_id
        ]
    return [
        record
        for record in history_records
        if not str(record.get("client_id", "")).strip()
    ]


def _build_cached_history_analysis_result(
    history_record: dict[str, Any],
    *,
    file_name: str,
    client_id: str,
) -> dict[str, Any]:
    """Build a lightweight history record append payload for cached scan requests."""
    return {
        "summary": {
            "file_name": file_name or str(history_record.get("file_name", "unknown")),
            "final_label": str(history_record.get("final_label", "unknown")),
            "final_confidence": _safe_float(history_record.get("final_confidence", 0.0)),
            "rule_score": _safe_float(history_record.get("rule_score", 0.0)),
        },
        "sha256": str(history_record.get("sha256", "")),
        "client_id": str(client_id).strip(),
        "recommendation": str(history_record.get("recommendation", "")),
        "report_timestamp": _utc_timestamp(),
    }


def _has_valid_api_token(expected_token: str) -> bool:
    """Return True when the incoming request contains the configured shared token."""
    token_header = str(request.headers.get(API_TOKEN_HEADER_NAME, "")).strip()
    if token_header and token_header == expected_token:
        return True

    authorization_header = str(request.headers.get("Authorization", "")).strip()
    if authorization_header.casefold().startswith("bearer "):
        return authorization_header[7:].strip() == expected_token
    return False


def _is_origin_allowed(origin: str, runtime_config: APIRuntimeConfig) -> bool:
    """Return True when the request origin is permitted by deployment config."""
    if not origin:
        return True
    if "*" in runtime_config.cors_allowed_origins:
        return True
    return origin in runtime_config.cors_allowed_origins


def _allowed_response_origin(origin: str, runtime_config: APIRuntimeConfig) -> str:
    """Return the Access-Control-Allow-Origin value for this response."""
    if "*" in runtime_config.cors_allowed_origins:
        return "*"
    if origin and origin in runtime_config.cors_allowed_origins:
        return origin
    return ""


def _looks_like_pdf(*, file_name: str, content_type: str, pdf_bytes: bytes) -> bool:
    """Return True when the upload or response appears to be a PDF."""
    normalized_name = str(file_name).strip().lower()
    normalized_type = str(content_type).strip().lower()
    if normalized_name.endswith(".pdf"):
        return True
    if "pdf" in normalized_type:
        return True
    return pdf_bytes[:5] == b"%PDF-"


def _filename_from_url(source_url: str) -> str:
    """Derive a practical filename from a source URL."""
    parsed_url = urllib.parse.urlparse(source_url)
    file_name = Path(parsed_url.path).name or "downloaded.pdf"
    if not file_name.lower().endswith(".pdf"):
        file_name = f"{file_name}.pdf"
    return file_name


def _safe_float(value: Any) -> float:
    """Convert a value to float safely."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _safe_int(value: Any, default: int) -> int:
    """Convert a value to int safely."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _utc_timestamp() -> str:
    """Return an ISO 8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
