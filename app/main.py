"""CLI entry point for PDF scanning and model training."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.cli import build_parser
from src.features.extractor import PDFFeatureExtractor
from src.fusion.decision import HybridDecisionLayer
from src.ml.classifier import MLClassifierError, MalwareClassifier, load_saved_model, train_from_csv
from src.parser.document_parser import PDFMalformedError, PDFParser, PDFParserError
from src.reporting.forensics import lookup_virustotal
from src.reporting.summary import build_analysis_summary, summary_to_console_text
from src.rules.engine import RuleEngine

AnalysisResult = dict[str, Any]
AnalysisSummary = dict[str, Any]

_SEVERITY_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def run_pdf_analysis(pdf_path: Path, classifier: MalwareClassifier) -> AnalysisSummary:
    return run_pdf_analysis_details(pdf_path, classifier)["summary"]


def run_pdf_analysis_details(
    pdf_path: Path,
    classifier: MalwareClassifier,
    *,
    sha256: str = "",
    file_name: str = "",
) -> AnalysisResult:
    parser = PDFParser()
    extractor = PDFFeatureExtractor()
    rule_engine = RuleEngine()
    fusion_layer = HybridDecisionLayer()

    parser_error: PDFParserError | None = None
    try:
        parser_output = parser.parse(pdf_path)
    except PDFParserError as exc:
        parser_error = exc
        parser_output = parser.read_raw_indicators(pdf_path)

    # Override temp filename with real filename if provided
    if file_name and isinstance(parser_output, dict):
        parser_output = {**parser_output, "file_name": file_name}

    features = extractor.extract(parser_output)
    rule_result = rule_engine.evaluate(features)
    ml_result = classifier.predict(features)

    if parser_error is None:
        final_decision = fusion_layer.combine(rule_result, ml_result)
    else:
        rule_result = _build_fallback_rule_result(rule_result, parser_error)
        final_decision = _build_fallback_final_decision(rule_result, ml_result)

    summary = build_analysis_summary(
        parser_output=parser_output,
        features=features,
        rule_result=rule_result,
        ml_result=ml_result,
        final_decision=final_decision,
    )

    # VirusTotal lookup — runs if sha256 is provided (API scans pass it in)
    virustotal_result: dict[str, Any] = {}
    if sha256:
        virustotal_result = lookup_virustotal(sha256)
        # If VirusTotal says malicious but our scanner says benign, escalate
        vt_verdict = virustotal_result.get("vt_verdict", "unknown")
        if vt_verdict == "malicious" and summary.get("final_label") == "benign":
            summary["final_label"] = "suspicious"
            summary["explanations"] = list(summary.get("explanations", [])) + [
                f"[high] virustotal-escalation: VirusTotal flagged this file as malicious "
                f"({virustotal_result.get('malicious', 0)} engines). "
                f"Verdict escalated from benign to suspicious."
            ]
            summary["triggered_rules"] = list(summary.get("triggered_rules", [])) + [
                "virustotal-malicious"
            ]

    return {
        "parser_output": parser_output,
        "features": features,
        "rule_result": rule_result,
        "ml_result": {
            "predicted_label": ml_result.predicted_label,
            "confidence": ml_result.confidence,
            "class_probabilities": ml_result.class_probabilities,
        },
        "final_decision": final_decision,
        "summary": summary,
        "virustotal": virustotal_result,
    }


def _build_fallback_rule_result(
    rule_result: dict[str, Any],
    parser_error: PDFParserError,
) -> dict[str, Any]:
    fallback_result = dict(rule_result)
    triggered_rules = list(fallback_result.get("triggered_rules", []))
    explanations = list(fallback_result.get("explanations", []))

    if "unreadable-pdf" not in triggered_rules:
        triggered_rules.append("unreadable-pdf")
    explanations.append(
        "[medium] unreadable-pdf: "
        f"The PDF could not be fully parsed ({parser_error}) and may itself be suspicious."
    )

    raw_score = max(int(fallback_result.get("risk_score_raw", 0)), 15)
    normalized_score = max(int(fallback_result.get("risk_score_normalized", 0)), 25)

    fallback_result["risk_score_raw"] = raw_score
    fallback_result["risk_score_normalized"] = normalized_score
    fallback_result["severity"] = _fallback_rule_severity(
        str(fallback_result.get("severity", "low"))
    )
    fallback_result["triggered_rules"] = triggered_rules
    fallback_result["explanations"] = explanations
    return fallback_result


def _build_fallback_final_decision(
    rule_result: dict[str, Any],
    ml_result: Any,
) -> dict[str, Any]:
    ml_confidence = _safe_float(getattr(ml_result, "confidence", 0.0))
    final_confidence = round(max(0.55, min(0.75, ml_confidence)), 3)

    return {
        "final_label": "suspicious",
        "final_confidence": final_confidence,
        "rule_score": _safe_float(rule_result.get("risk_score_normalized", 0.0)),
        "rule_severity": str(rule_result.get("severity", "medium")),
        "ml_label": str(getattr(ml_result, "predicted_label", "unknown")),
        "ml_confidence": ml_confidence,
        "triggered_rules": list(rule_result.get("triggered_rules", [])),
        "explanations": list(rule_result.get("explanations", [])),
    }


def _fallback_rule_severity(current_severity: str) -> str:
    safe_severity = current_severity if current_severity in _SEVERITY_ORDER else "low"
    if _SEVERITY_ORDER[safe_severity] < _SEVERITY_ORDER["medium"]:
        return "medium"
    return safe_severity


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _validate_pdf_path(pdf_path: Path) -> None:
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF file not found: {pdf_path}")
    if not pdf_path.is_file():
        raise FileNotFoundError(f"PDF file not found: {pdf_path}")
    if pdf_path.suffix.lower() != ".pdf":
        raise ValueError(f"Expected a PDF file, got: {pdf_path}")


def _format_scan_folder_result(summary: AnalysisSummary) -> str:
    return (
        f"{summary['file_name']} | final={summary['final_label']} | "
        f"confidence={summary['final_confidence']:.2f} | "
        f"rule={summary['rule_severity']}"
    )


def _handle_scan(file_path: Path, model_dir: Path) -> int:
    _validate_pdf_path(file_path)
    classifier = load_saved_model(model_dir=model_dir)
    summary = run_pdf_analysis(file_path, classifier)
    print(summary_to_console_text(summary))
    return 0


def _handle_scan_folder(directory: Path, model_dir: Path, *, full: bool = False) -> int:
    if not directory.exists():
        raise FileNotFoundError(f"Folder not found: {directory}")
    if not directory.is_dir():
        raise NotADirectoryError(f"Invalid folder: {directory}")

    pdf_files = sorted(path for path in directory.iterdir() if path.is_file() and path.suffix.lower() == ".pdf")
    if not pdf_files:
        raise FileNotFoundError(f"No PDF files found in folder: {directory}")

    classifier = load_saved_model(model_dir=model_dir)
    had_errors = False

    for pdf_file in pdf_files:
        try:
            summary = run_pdf_analysis(pdf_file, classifier)
            print(_format_scan_folder_result(summary))
            if full:
                print(summary_to_console_text(summary))
                print()
        except (FileNotFoundError, PDFParserError, MLClassifierError) as exc:
            had_errors = True
            print(f"{pdf_file.name} | error={exc}")

    return 1 if had_errors else 0


def _handle_train(csv_path: Path, model_dir: Path) -> int:
    """Train baseline models from a CSV dataset and print evaluation results."""
    training_result = train_from_csv(csv_path, model_dir=model_dir)
    best_metrics = training_result["best_model_metrics"]

    print("Training completed successfully.")
    print(f"Dataset rows: {training_result.get('dataset_row_count', 'N/A')}")
    print("Class distribution:")
    class_distribution = training_result.get("class_distribution", {})
    if class_distribution:
        for label, count in class_distribution.items():
            print(f"{label}: {count}")
    else:
        print("No class distribution available.")

    print(f"Recommended baseline: {training_result['recommended_baseline']}")
    print(f"Best selected model: {training_result['best_model_name']}")
    print(f"Saved model path: {training_result['model_path']}")
    print(f"Feature columns path: {training_result['feature_columns_path']}")
    print(f"Saved metrics/report path: {training_result['metrics_summary_path']}")
    print(f"Confusion matrix chart: {training_result['confusion_matrix_path']}")
    print(f"Model comparison chart: {training_result['model_comparison_path']}")
    print(f"Saved reports directory: {training_result['reports_dir']}")
    print()
    print("Best model metrics:")
    print(f"- Accuracy: {best_metrics['accuracy']:.3f}")
    print(f"- Precision: {best_metrics['precision']:.3f}")
    print(f"- Recall: {best_metrics['recall']:.3f}")
    print(f"- F1-score: {best_metrics['f1_score']:.3f}")
    print("- Classification report:")
    print(best_metrics["classification_report"])
    print()
    print("All model F1-scores:")
    for model_name, metrics in training_result["all_model_metrics"].items():
        print(f"- {model_name}: {metrics['f1_score']:.3f}")

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return _handle_scan(args.file_path, args.model_dir)
        if args.command == "scan-folder":
            return _handle_scan_folder(args.directory, args.model_dir, full=args.full)
        if args.command == "train":
            return _handle_train(args.csv_path, args.model_dir)
        parser.print_help()
        return 1
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (NotADirectoryError, PDFParserError, PDFMalformedError, MLClassifierError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
