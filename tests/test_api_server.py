"""Tests for hosted-ready Flask API behavior and extension-facing responses."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import api_server
from app.runtime_config import API_TOKEN_HEADER_NAME, build_runtime_config
from src.reporting.history import load_scan_history


class APIServerTestCase(unittest.TestCase):
    """Validate hosted API routes, auth, CORS, and response compatibility."""

    def setUp(self) -> None:
        """Create a Flask test client for each test."""
        self.runtime_config = build_runtime_config(
            host="127.0.0.1",
            port=8008,
            public_base_url="https://api.example.com",
            dashboard_public_url="https://dashboard.example.com",
            model_dir=PROJECT_ROOT / "models",
            data_dir=PROJECT_ROOT / "data",
            cors_allowed_origins=("https://dashboard.example.com", "chrome-extension://test-extension-id"),
            api_auth_token="secret-token",
        )
        self.app = api_server.create_app(config=self.runtime_config)
        self.client = self.app.test_client()

    def test_build_runtime_config_reads_environment_style_inputs(self) -> None:
        """Build runtime config from explicit values in a deployment-friendly shape."""
        runtime_config = build_runtime_config(
            host="0.0.0.0",
            port="9000",
            public_base_url="https://api.example.com/",
            dashboard_public_url="https://dashboard.example.com/",
            model_dir="models",
            data_dir="data",
            cors_allowed_origins="https://dashboard.example.com,chrome-extension://abc123",
            api_auth_token="top-secret",
            recent_limit="9",
        )

        self.assertEqual(runtime_config.host, "0.0.0.0")
        self.assertEqual(runtime_config.port, 9000)
        self.assertEqual(runtime_config.public_base_url, "https://api.example.com")
        self.assertEqual(runtime_config.dashboard_public_url, "https://dashboard.example.com")
        self.assertEqual(runtime_config.api_auth_token, "top-secret")
        self.assertEqual(runtime_config.recent_limit, 9)
        self.assertIn("chrome-extension://abc123", runtime_config.cors_allowed_origins)

    def test_hosted_runtime_config_defaults_cors_to_dashboard_origin(self) -> None:
        """Use a narrower default CORS origin in hosted mode when none is configured."""
        runtime_config = build_runtime_config(
            public_base_url="https://api.example.com",
            dashboard_public_url="https://dashboard.example.com",
            cors_allowed_origins=None,
        )

        self.assertEqual(runtime_config.cors_allowed_origins, ("https://dashboard.example.com",))

    def test_health_endpoint_returns_service_status_without_auth(self) -> None:
        """Return a simple health payload for public reachability checks."""
        response = self.client.get("/api/health")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["service"], "Advanced PDFSafeScan API")
        self.assertEqual(payload["public_base_url"], "https://api.example.com")
        self.assertTrue(payload["authentication_required"])

    def test_recent_scans_requires_auth_when_token_is_configured(self) -> None:
        """Reject protected requests that do not include the configured shared token."""
        response = self.client.get("/api/scan/recent")
        payload = response.get_json()

        self.assertEqual(response.status_code, 401)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_code"], "unauthorized")

    @patch("app.api_server.load_analyst_reviews_by_sha256")
    @patch("app.api_server.load_scan_history")
    def test_recent_scans_accepts_bearer_authorization_header(
        self,
        mock_load_scan_history,
        mock_load_analyst_reviews_by_sha256,
    ) -> None:
        """Allow hosted clients to authenticate with Authorization: Bearer."""
        mock_load_scan_history.return_value = []
        mock_load_analyst_reviews_by_sha256.return_value = {}

        response = self.client.get(
            "/api/scan/recent",
            headers={"Authorization": "Bearer secret-token"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")

    @patch("app.api_server.load_analyst_reviews_by_sha256")
    @patch("app.api_server.load_scan_history")
    def test_recent_scans_endpoint_returns_extension_rows_with_valid_token(
        self,
        mock_load_scan_history,
        mock_load_analyst_reviews_by_sha256,
    ) -> None:
        """Return recent scan rows merged with analyst review fields when auth succeeds."""
        mock_load_scan_history.return_value = [
            {
                "timestamp": "2026-03-29T11:00:00+00:00",
                "file_name": "sample.pdf",
                "sha256": "abc123",
                "final_label": "suspicious",
                "final_confidence": 0.81,
                "rule_score": 67.0,
                "recommendation": "Open with caution.",
            }
        ]
        mock_load_analyst_reviews_by_sha256.return_value = {
            "abc123": {
                "review_status": "Under Review",
                "priority": "High",
                "disposition": "Suspicious",
                "analyst_note": "Queued for analyst triage.",
            }
        }

        response = self.client.get(
            "/api/scan/recent?limit=5",
            headers={API_TOKEN_HEADER_NAME: "secret-token"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["file_name"], "sample.pdf")
        self.assertEqual(payload["items"][0]["review_status"], "Under Review")
        self.assertEqual(payload["dashboard_url"], "https://dashboard.example.com")

    @patch("app.api_server.load_analyst_reviews_by_sha256")
    @patch("app.api_server.load_scan_history")
    def test_recent_scans_filters_history_by_request_client_id(
        self,
        mock_load_scan_history,
        mock_load_analyst_reviews_by_sha256,
    ) -> None:
        """Return only history rows that belong to the requesting installation id."""
        mock_load_scan_history.return_value = [
            {
                "timestamp": "2026-03-29T11:00:00+00:00",
                "file_name": "client-a.pdf",
                "sha256": "aaa111",
                "client_id": "client-a",
                "final_label": "suspicious",
                "final_confidence": 0.81,
                "rule_score": 67.0,
                "recommendation": "Open with caution.",
            },
            {
                "timestamp": "2026-03-29T11:05:00+00:00",
                "file_name": "client-b.pdf",
                "sha256": "bbb222",
                "client_id": "client-b",
                "final_label": "malicious",
                "final_confidence": 0.98,
                "rule_score": 92.0,
                "recommendation": "Do not open.",
            },
        ]
        mock_load_analyst_reviews_by_sha256.return_value = {}

        response = self.client.get(
            "/api/scan/recent?limit=5",
            headers={
                API_TOKEN_HEADER_NAME: "secret-token",
                api_server.CLIENT_ID_HEADER_NAME: "client-a",
            },
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["file_name"], "client-a.pdf")

    @patch("app.api_server.load_analyst_reviews_by_sha256")
    @patch("app.api_server.load_scan_history")
    def test_recent_scans_without_client_id_returns_only_anonymous_records(
        self,
        mock_load_scan_history,
        mock_load_analyst_reviews_by_sha256,
    ) -> None:
        """Keep blank-client fallback scoped to older anonymous records only."""
        mock_load_scan_history.return_value = [
            {
                "timestamp": "2026-03-29T11:00:00+00:00",
                "file_name": "anonymous.pdf",
                "sha256": "anon111",
                "client_id": "",
                "final_label": "benign",
                "final_confidence": 0.91,
                "rule_score": 4.0,
                "recommendation": "Safe to open.",
            },
            {
                "timestamp": "2026-03-29T11:05:00+00:00",
                "file_name": "client-b.pdf",
                "sha256": "bbb222",
                "client_id": "client-b",
                "final_label": "malicious",
                "final_confidence": 0.98,
                "rule_score": 92.0,
                "recommendation": "Do not open.",
            },
        ]
        mock_load_analyst_reviews_by_sha256.return_value = {}

        response = self.client.get(
            "/api/scan/recent?limit=5",
            headers={API_TOKEN_HEADER_NAME: "secret-token"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["file_name"], "anonymous.pdf")

    def test_file_scan_endpoint_rejects_missing_file(self) -> None:
        """Reject file scan requests that do not include an uploaded PDF."""
        response = self.client.post(
            "/api/scan/file",
            json={},
            headers={API_TOKEN_HEADER_NAME: "secret-token"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 400)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_code"], "missing_file")

    def test_file_scan_endpoint_rejects_non_pdf_upload(self) -> None:
        """Reject uploads that do not appear to be PDFs."""
        response = self.client.post(
            "/api/scan/file",
            data={
                "file": (io.BytesIO(b"plain text payload"), "notes.txt"),
            },
            content_type="multipart/form-data",
            headers={API_TOKEN_HEADER_NAME: "secret-token"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 415)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_code"], "unsupported_content_type")

    def test_file_scan_endpoint_rejects_oversized_upload(self) -> None:
        """Reject uploads that exceed the API's supported maximum size."""
        response = self.client.post(
            "/api/scan/file",
            data={
                "file": (io.BytesIO(b"%PDF-" + b"A" * (16 * 1024 * 1024)), "large.pdf"),
            },
            content_type="multipart/form-data",
            headers={API_TOKEN_HEADER_NAME: "secret-token"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 413)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_code"], "request_too_large")

    @patch("app.api_server._scan_pdf_bytes")
    def test_file_scan_endpoint_returns_extension_style_json(self, mock_scan_pdf_bytes) -> None:
        """Return extension-friendly JSON for a successful uploaded PDF scan."""
        mock_scan_pdf_bytes.return_value = {
            "status": "ok",
            "cached": False,
            "timestamp": "2026-03-29T12:00:00+00:00",
            "file_name": "sample.pdf",
            "sha256": "abc123",
            "final_label": "suspicious",
            "final_confidence": 0.84,
            "rule_score": 68.0,
            "rule_severity": "high",
            "ml_label": "malicious",
            "ml_confidence": 0.74,
            "triggered_rules": ["embedded-js"],
            "explanations": ["JavaScript action detected."],
            "suspicious_indicators_found": ["/JavaScript (1)"],
            "recommendation": "Open with caution.",
            "review_status": "New",
            "priority": "Medium",
            "disposition": "Suspicious",
            "analyst_note": "",
        }

        response = self.client.post(
            "/api/scan/file",
            data={
                "file": (io.BytesIO(b"%PDF-1.7 sample"), "sample.pdf"),
            },
            content_type="multipart/form-data",
            headers={API_TOKEN_HEADER_NAME: "secret-token"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["file_name"], "sample.pdf")
        self.assertEqual(payload["final_label"], "suspicious")
        self.assertEqual(payload["public_base_url"], "https://api.example.com")

    @patch("app.api_server._scan_pdf_bytes")
    def test_file_scan_endpoint_passes_client_id_into_scan_helper(self, mock_scan_pdf_bytes) -> None:
        """Forward the installation id header into the shared scan helper."""
        mock_scan_pdf_bytes.return_value = {
            "status": "ok",
            "cached": False,
            "file_name": "sample.pdf",
            "final_label": "benign",
        }

        response = self.client.post(
            "/api/scan/file",
            data={"file": (io.BytesIO(b"%PDF-1.7 sample"), "sample.pdf")},
            content_type="multipart/form-data",
            headers={
                API_TOKEN_HEADER_NAME: "secret-token",
                api_server.CLIENT_ID_HEADER_NAME: "client-a",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_scan_pdf_bytes.call_args.kwargs["client_id"], "client-a")

    def test_url_scan_endpoint_rejects_missing_payload(self) -> None:
        """Reject URL scan requests that do not provide a JSON body."""
        response = self.client.post(
            "/api/scan/url",
            data="not-json",
            content_type="application/json",
            headers={API_TOKEN_HEADER_NAME: "secret-token"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 400)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_code"], "invalid_request")

    def test_url_scan_endpoint_rejects_missing_url(self) -> None:
        """Reject URL scan requests without a URL value."""
        response = self.client.post(
            "/api/scan/url",
            json={},
            headers={API_TOKEN_HEADER_NAME: "secret-token"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 400)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_code"], "missing_url")

    def test_url_scan_endpoint_rejects_invalid_scheme(self) -> None:
        """Reject non-http and non-https source URLs before attempting a fetch."""
        response = self.client.post(
            "/api/scan/url",
            json={"url": "file:///tmp/sample.pdf"},
            headers={API_TOKEN_HEADER_NAME: "secret-token"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 400)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_code"], "invalid_url")

    @patch("app.api_server._scan_pdf_url")
    def test_url_scan_endpoint_returns_extension_style_json(self, mock_scan_pdf_url) -> None:
        """Return extension-friendly JSON for a successful URL scan."""
        mock_scan_pdf_url.return_value = {
            "status": "ok",
            "cached": True,
            "source_url": "https://example.com/sample.pdf",
            "timestamp": "2026-03-29T12:00:00+00:00",
            "file_name": "sample.pdf",
            "sha256": "abc123",
            "final_label": "malicious",
            "final_confidence": 0.97,
            "rule_score": 91.0,
            "rule_severity": "critical",
            "ml_label": "malicious",
            "ml_confidence": 0.96,
            "triggered_rules": ["embedded-js"],
            "explanations": ["Embedded JavaScript launch action detected."],
            "suspicious_indicators_found": ["/JavaScript (1)"],
            "recommendation": "Do not open.",
            "review_status": "Escalated",
            "priority": "Critical",
            "disposition": "Malicious",
            "analyst_note": "Known malicious sample.",
        }

        response = self.client.post(
            "/api/scan/url",
            json={"url": "https://example.com/sample.pdf"},
            headers={API_TOKEN_HEADER_NAME: "secret-token"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["cached"])
        self.assertEqual(payload["source_url"], "https://example.com/sample.pdf")
        self.assertEqual(payload["review_status"], "Escalated")

    @patch("app.api_server.urllib.request.urlopen")
    @patch("app.api_server._scan_pdf_bytes")
    def test_scan_pdf_url_fetches_pdf_content_and_preserves_source_url(
        self,
        mock_scan_pdf_bytes,
        mock_urlopen,
    ) -> None:
        """Fetch PDF bytes from a URL and pass them into the shared scan helper."""

        class _FakeResponse:
            def __init__(self) -> None:
                self.headers = {"Content-Type": "application/pdf"}

            def read(self) -> bytes:
                return b"%PDF-1.7 url"

            def __enter__(self) -> "_FakeResponse":
                return self

            def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
                return None

        mock_urlopen.return_value = _FakeResponse()
        mock_scan_pdf_bytes.return_value = {
            "status": "ok",
            "source_url": "https://example.com/sample.pdf",
            "file_name": "sample.pdf",
        }

        payload = api_server._scan_pdf_url(
            "https://example.com/sample.pdf",
            model_dir=PROJECT_ROOT / "models",
        )

        self.assertEqual(payload["status"], "ok")
        mock_scan_pdf_bytes.assert_called_once()

    @patch("app.api_server.build_scan_response_from_history_record")
    @patch("app.api_server.load_analyst_reviews_by_sha256")
    @patch("app.api_server.find_cached_history_record_by_sha256")
    @patch("app.api_server.load_scan_history")
    @patch("app.api_server.compute_sha256")
    def test_scan_pdf_bytes_uses_cached_history_record_when_available(
        self,
        mock_compute_sha256,
        mock_load_scan_history,
        mock_find_cached_history_record,
        mock_load_analyst_reviews_by_sha256,
        mock_build_scan_response_from_history_record,
    ) -> None:
        """Reuse cached history data instead of rerunning the PDF pipeline."""
        mock_compute_sha256.return_value = "abc123"
        mock_load_scan_history.return_value = [{"sha256": "abc123", "timestamp": "2026-03-29T10:00:00+00:00"}]
        mock_find_cached_history_record.return_value = {
            "timestamp": "2026-03-29T10:00:00+00:00",
            "file_name": "cached.pdf",
            "sha256": "abc123",
            "final_label": "malicious",
            "final_confidence": 0.97,
            "rule_score": 91.0,
            "recommendation": "Do not open.",
        }
        mock_load_analyst_reviews_by_sha256.return_value = {
            "abc123": {"review_status": "Escalated", "priority": "Critical"}
        }
        mock_build_scan_response_from_history_record.return_value = {
            "status": "ok",
            "cached": True,
            "file_name": "cached.pdf",
        }

        with patch("app.api_server.append_scan_history_records") as mock_append_scan_history_records:
            payload = api_server._scan_pdf_bytes(
                pdf_bytes=b"%PDF-1.7",
                file_name="cached.pdf",
                model_dir=PROJECT_ROOT / "models",
                source_url="https://example.com/cached.pdf",
                client_id="client-a",
                history_path=PROJECT_ROOT / "data" / "history" / "scan_history.json",
                review_notes_path=PROJECT_ROOT / "data" / "history" / "analyst_reviews.json",
            )

        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["cached"])
        mock_build_scan_response_from_history_record.assert_called_once()
        mock_append_scan_history_records.assert_called_once()
        cached_append_payload = mock_append_scan_history_records.call_args.args[0][0][1]
        self.assertEqual(cached_append_payload["client_id"], "client-a")

    @patch("app.api_server.append_scan_history_records")
    @patch("app.api_server.build_scan_response_from_analysis")
    @patch("app.api_server.recommendation_for_verdict")
    @patch("app.api_server.run_pdf_analysis_details")
    @patch("app.api_server._get_classifier")
    @patch("app.api_server.load_analyst_reviews_by_sha256")
    @patch("app.api_server.find_cached_history_record_by_sha256")
    @patch("app.api_server.load_scan_history")
    @patch("app.api_server.compute_sha256")
    def test_scan_pdf_bytes_runs_pipeline_when_cache_missing(
        self,
        mock_compute_sha256,
        mock_load_scan_history,
        mock_find_cached_history_record,
        mock_load_analyst_reviews_by_sha256,
        mock_get_classifier,
        mock_run_pdf_analysis_details,
        mock_recommendation_for_verdict,
        mock_build_scan_response_from_analysis,
        mock_append_scan_history_records,
    ) -> None:
        """Run the existing analysis pipeline and persist history when no cache entry exists."""
        mock_compute_sha256.return_value = "freshhash"
        mock_load_scan_history.return_value = []
        mock_find_cached_history_record.return_value = None
        mock_load_analyst_reviews_by_sha256.return_value = {}
        mock_get_classifier.return_value = object()
        mock_run_pdf_analysis_details.return_value = {
            "summary": {
                "file_name": "fresh.pdf",
                "final_label": "suspicious",
                "final_confidence": 0.82,
                "rule_score": 66.0,
                "rule_severity": "high",
                "ml_label": "malicious",
                "ml_confidence": 0.74,
                "triggered_rules": ["embedded-js"],
                "explanations": ["JavaScript action detected."],
                "suspicious_indicators_found": ["/JavaScript (1)"],
            }
        }
        mock_recommendation_for_verdict.return_value = "Open with caution."
        mock_build_scan_response_from_analysis.return_value = {
            "status": "ok",
            "cached": False,
            "file_name": "fresh.pdf",
            "final_label": "suspicious",
        }

        payload = api_server._scan_pdf_bytes(
            pdf_bytes=b"%PDF-1.7 fresh",
            file_name="fresh.pdf",
            model_dir=PROJECT_ROOT / "models",
            source_url="https://example.com/fresh.pdf",
            client_id="client-a",
            history_path=PROJECT_ROOT / "data" / "history" / "scan_history.json",
            review_notes_path=PROJECT_ROOT / "data" / "history" / "analyst_reviews.json",
        )

        self.assertEqual(payload["status"], "ok")
        self.assertFalse(payload["cached"])
        mock_run_pdf_analysis_details.assert_called_once()
        mock_append_scan_history_records.assert_called_once()
        mock_build_scan_response_from_analysis.assert_called_once()
        appended_analysis_result = mock_append_scan_history_records.call_args.args[0][0][1]
        self.assertEqual(appended_analysis_result["client_id"], "client-a")

    def test_load_scan_history_remains_backward_compatible_without_client_id(self) -> None:
        """Normalize older history rows safely when client_id is missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            history_path = Path(temp_dir) / "scan_history.json"
            history_path.write_text(
                json.dumps(
                    [
                        {
                            "timestamp": "2026-03-29T10:00:00+00:00",
                            "file_name": "legacy.pdf",
                            "sha256": "legacy123",
                            "final_label": "benign",
                            "final_confidence": 0.9,
                            "rule_score": 2.0,
                            "recommendation": "Safe to open.",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            history_records = load_scan_history(history_path=history_path)

        self.assertEqual(len(history_records), 1)
        self.assertEqual(history_records[0]["client_id"], "")

    def test_json_base64_file_payload_is_accepted(self) -> None:
        """Support a lightweight JSON upload format for extension-friendly file scans."""
        with patch("app.api_server._scan_pdf_bytes") as mock_scan_pdf_bytes:
            mock_scan_pdf_bytes.return_value = {
                "status": "ok",
                "cached": False,
                "file_name": "sample.pdf",
                "final_label": "benign",
            }
            response = self.client.post(
                "/api/scan/file",
                data=json.dumps(
                    {
                        "file_name": "sample.pdf",
                        "content_type": "application/pdf",
                        "file_bytes_base64": "JVBERi0xLjc=",
                    }
                ),
                content_type="application/json",
                headers={API_TOKEN_HEADER_NAME: "secret-token"},
            )

        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "ok")

    def test_preflight_response_includes_allowed_origin(self) -> None:
        """Return CORS headers that permit configured hosted extension/dashboard callers."""
        response = self.client.options(
            "/api/scan/url",
            headers={
                "Origin": "chrome-extension://test-extension-id",
                "Access-Control-Request-Method": "POST",
            },
        )

        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "chrome-extension://test-extension-id")
        self.assertIn(API_TOKEN_HEADER_NAME, response.headers.get("Access-Control-Allow-Headers", ""))
        self.assertIn(api_server.CLIENT_ID_HEADER_NAME, response.headers.get("Access-Control-Allow-Headers", ""))

    def test_disallowed_origin_is_rejected(self) -> None:
        """Reject requests from origins outside the configured allowlist."""
        response = self.client.get(
            "/api/health",
            headers={"Origin": "https://evil.example.com"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 403)
        self.assertEqual(payload["error_code"], "origin_not_allowed")


if __name__ == "__main__":
    unittest.main()

