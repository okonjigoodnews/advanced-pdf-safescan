"""Feature engineering helpers for parsed PDF inspection results."""

from __future__ import annotations

from typing import TypeAlias

from src.parser.document_parser import ParsedPDF


FeatureVector: TypeAlias = dict[str, float | int | bool]

_KEYWORD_TO_FEATURE_NAME: dict[str, str] = {
    "/JavaScript": "javascript",
    "/JS": "js",
    "/OpenAction": "openaction",
    "/AA": "aa",
    "/Launch": "launch",
    "/URI": "uri",
    "/EmbeddedFile": "embeddedfile",
    "/Encrypt": "encrypt",
    "/ObjStm": "objstm",
    "/RichMedia": "richmedia",
    "/AcroForm": "acroform",
}


class PDFFeatureExtractor:
    """Convert parsed PDF inspection output into stable engineered features."""

    def extract(self, parsed_pdf: ParsedPDF | dict[str, object]) -> FeatureVector:
        """Return a flat dictionary of ML-ready features with safe defaults."""
        keyword_counts = self._get_keyword_counts(parsed_pdf)

        file_size = self._safe_int(parsed_pdf.get("file_size", 0))
        page_count = self._safe_int(parsed_pdf.get("page_count", 0))
        metadata_field_count = self._safe_int(parsed_pdf.get("metadata_field_count", 0))
        suspicious_keyword_total = self._safe_int(
            parsed_pdf.get("suspicious_keyword_total", sum(keyword_counts.values()))
        )

        features: FeatureVector = {
            "file_size": file_size,
            "page_count": page_count,
            "metadata_field_count": metadata_field_count,
            "suspicious_keyword_total": suspicious_keyword_total,
            "is_encrypted": self._safe_bool(parsed_pdf.get("is_encrypted", False)),
        }

        for keyword, feature_name in _KEYWORD_TO_FEATURE_NAME.items():
            count = self._safe_int(keyword_counts.get(keyword, 0))
            features[f"{feature_name}_count"] = count
            features[f"has_{feature_name}"] = count > 0

        features["action_keyword_total"] = (
            self._safe_int(features["openaction_count"])
            + self._safe_int(features["aa_count"])
            + self._safe_int(features["launch_count"])
            + self._safe_int(features["uri_count"])
        )
        features["embedded_or_script_total"] = (
            self._safe_int(features["javascript_count"])
            + self._safe_int(features["js_count"])
            + self._safe_int(features["embeddedfile_count"])
            + self._safe_int(features["richmedia_count"])
        )
        features["stream_like_keyword_total"] = (
            self._safe_int(features["objstm_count"])
            + self._safe_int(features["embeddedfile_count"])
            + self._safe_int(features["richmedia_count"])
        )
        features["high_risk_keyword_total"] = (
            self._safe_int(features["javascript_count"])
            + self._safe_int(features["js_count"])
            + self._safe_int(features["openaction_count"])
            + self._safe_int(features["aa_count"])
            + self._safe_int(features["launch_count"])
            + self._safe_int(features["embeddedfile_count"])
            + self._safe_int(features["richmedia_count"])
            + self._safe_int(features["acroform_count"])
        )
        features["keyword_density_per_page"] = suspicious_keyword_total / max(page_count, 1)

        return features

    def _get_keyword_counts(self, parsed_pdf: ParsedPDF | dict[str, object]) -> dict[str, int]:
        """Return suspicious keyword counts from parser output with safe defaults."""
        raw_counts = parsed_pdf.get("suspicious_keyword_counts", {})
        if not isinstance(raw_counts, dict):
            return {}
        return {str(key): self._safe_int(value) for key, value in raw_counts.items()}

    def _safe_int(self, value: object) -> int:
        """Convert a value to an integer, falling back to zero."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _safe_bool(self, value: object) -> bool:
        """Convert a value to a boolean using Python truthiness rules."""
        return bool(value)
