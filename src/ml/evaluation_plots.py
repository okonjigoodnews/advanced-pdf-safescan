"""Training evaluation artifact helpers for model comparison and reporting."""

from __future__ import annotations

import json
from importlib import import_module
from pathlib import Path
from typing import Any

from src.ml.classifier import MLDependencyError

DEFAULT_METRICS_SUMMARY_FILENAME = "metrics_summary.json"
DEFAULT_CONFUSION_MATRIX_FILENAME = "best_model_confusion_matrix.png"
DEFAULT_MODEL_COMPARISON_FILENAME = "model_f1_comparison.png"


def save_training_evaluation_artifacts(
    *,
    evaluation_results: dict[str, dict[str, Any]],
    best_model_name: str,
    best_model: Any,
    x_test: Any,
    y_test: Any,
    output_dir: str | Path,
) -> dict[str, str]:
    """Save JSON and chart artifacts for a completed training run."""
    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    metrics_summary_path = report_dir / DEFAULT_METRICS_SUMMARY_FILENAME
    confusion_matrix_path = report_dir / DEFAULT_CONFUSION_MATRIX_FILENAME
    model_comparison_path = report_dir / DEFAULT_MODEL_COMPARISON_FILENAME

    metrics_payload = {
        "recommended_baseline": "random_forest",
        "best_model_name": best_model_name,
        "best_model_metrics": dict(evaluation_results.get(best_model_name, {})),
        "all_model_metrics": {
            model_name: dict(metrics)
            for model_name, metrics in evaluation_results.items()
        },
    }
    metrics_summary_path.write_text(
        json.dumps(metrics_payload, indent=2),
        encoding="utf-8",
    )

    pyplot, confusion_matrix = _load_plot_dependencies()
    _save_confusion_matrix_plot(
        pyplot=pyplot,
        confusion_matrix=confusion_matrix,
        best_model=best_model,
        x_test=x_test,
        y_test=y_test,
        output_path=confusion_matrix_path,
    )
    _save_model_comparison_plot(
        pyplot=pyplot,
        evaluation_results=evaluation_results,
        best_model_name=best_model_name,
        output_path=model_comparison_path,
    )

    return {
        "reports_dir": str(report_dir),
        "metrics_summary_path": str(metrics_summary_path),
        "confusion_matrix_path": str(confusion_matrix_path),
        "model_comparison_path": str(model_comparison_path),
    }


def _save_confusion_matrix_plot(
    *,
    pyplot: Any,
    confusion_matrix: Any,
    best_model: Any,
    x_test: Any,
    y_test: Any,
    output_path: Path,
) -> None:
    """Save a simple confusion matrix figure for the best model."""
    y_true = [str(value) for value in _to_python_list(y_test)]
    predictions = [str(value) for value in best_model.predict(x_test)]
    labels = sorted(set(y_true + predictions))
    matrix = confusion_matrix(y_true, predictions, labels=labels)

    figure, axis = pyplot.subplots(figsize=(6, 4.5))
    image = axis.imshow(matrix, cmap="Blues")
    figure.colorbar(image, ax=axis, fraction=0.046, pad=0.04)
    axis.set_title("Best Model Confusion Matrix")
    axis.set_xlabel("Predicted label")
    axis.set_ylabel("True label")
    axis.set_xticks(range(len(labels)))
    axis.set_xticklabels(labels, rotation=20, ha="right")
    axis.set_yticks(range(len(labels)))
    axis.set_yticklabels(labels)

    for row_index, row in enumerate(matrix):
        for column_index, value in enumerate(row):
            axis.text(
                column_index,
                row_index,
                str(int(value)),
                ha="center",
                va="center",
                color="#0f172a",
                fontsize=10,
            )

    figure.tight_layout()
    figure.savefig(output_path, dpi=150, bbox_inches="tight")
    pyplot.close(figure)


def _save_model_comparison_plot(
    *,
    pyplot: Any,
    evaluation_results: dict[str, dict[str, Any]],
    best_model_name: str,
    output_path: Path,
) -> None:
    """Save a simple F1-score comparison chart for all candidate models."""
    model_names = list(evaluation_results.keys())
    f1_scores = [float(evaluation_results[name].get("f1_score", 0.0)) for name in model_names]
    colors = [
        "#2563eb" if model_name == best_model_name else "#94a3b8"
        for model_name in model_names
    ]

    figure, axis = pyplot.subplots(figsize=(7, 4.5))
    bars = axis.bar(model_names, f1_scores, color=colors)
    axis.set_ylim(0, 1)
    axis.set_ylabel("F1-score")
    axis.set_title("Model Comparison")

    for bar, score in zip(bars, f1_scores):
        axis.text(
            bar.get_x() + bar.get_width() / 2,
            score + 0.02,
            f"{score:.3f}",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    figure.tight_layout()
    figure.savefig(output_path, dpi=150, bbox_inches="tight")
    pyplot.close(figure)


def _load_plot_dependencies() -> tuple[Any, Any]:
    """Import plotting and confusion matrix helpers lazily."""
    try:
        matplotlib_module = import_module("matplotlib")
        matplotlib_module.use("Agg")
        pyplot_module = import_module("matplotlib.pyplot")
        metrics_module = import_module("sklearn.metrics")
    except ImportError as exc:
        raise MLDependencyError(
            "matplotlib and scikit-learn are required to generate training evaluation charts."
        ) from exc

    return pyplot_module, metrics_module.confusion_matrix


def _to_python_list(values: Any) -> list[Any]:
    """Convert a vector-like object into a Python list."""
    if hasattr(values, "tolist"):
        return list(values.tolist())
    return list(values)
