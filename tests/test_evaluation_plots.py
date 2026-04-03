"""Tests for training evaluation artifact generation helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ml.evaluation_plots import save_training_evaluation_artifacts


class _FakeSeries:
    """Small series stand-in with list conversion support."""

    def __init__(self, values: list[str]) -> None:
        self.values = values

    def tolist(self) -> list[str]:
        """Return the stored values."""
        return list(self.values)


class _FakeModel:
    """Small estimator stand-in with deterministic predictions."""

    def predict(self, x_input: object) -> list[str]:
        """Return deterministic labels for confusion matrix generation."""
        _ = x_input
        return ["benign", "malicious"]


class _FakeAxis:
    """Minimal plotting axis stub."""

    def imshow(self, matrix: object, cmap: str = "Blues") -> object:
        _ = (matrix, cmap)
        return object()

    def set_title(self, title: str) -> None:
        _ = title

    def set_xlabel(self, label: str) -> None:
        _ = label

    def set_ylabel(self, label: str) -> None:
        _ = label

    def set_xticks(self, ticks: object) -> None:
        _ = ticks

    def set_xticklabels(self, labels: object, rotation: int = 0, ha: str = "center") -> None:
        _ = (labels, rotation, ha)

    def set_yticks(self, ticks: object) -> None:
        _ = ticks

    def set_yticklabels(self, labels: object) -> None:
        _ = labels

    def text(
        self,
        x_pos: float,
        y_pos: float,
        value: str,
        *,
        ha: str,
        va: str,
        color: str | None = None,
        fontsize: int,
    ) -> None:
        _ = (x_pos, y_pos, value, ha, va, color, fontsize)

    def bar(self, model_names: list[str], f1_scores: list[float], color: list[str]) -> list[object]:
        _ = color
        bars: list[object] = []
        for index, _ in enumerate(model_names):
            bars.append(_FakeBar(index, f1_scores[index]))
        return bars

    def set_ylim(self, low: float, high: float) -> None:
        _ = (low, high)


class _FakeBar:
    """Minimal bar stub for label positioning."""

    def __init__(self, x_pos: float, height: float) -> None:
        self._x_pos = x_pos
        self._height = height

    def get_x(self) -> float:
        """Return the x position."""
        return self._x_pos

    def get_width(self) -> float:
        """Return the bar width."""
        return 0.8

    def get_height(self) -> float:
        """Return the bar height."""
        return self._height


class _FakeFigure:
    """Minimal plotting figure stub."""

    def colorbar(self, image: object, ax: object, fraction: float, pad: float) -> None:
        _ = (image, ax, fraction, pad)

    def tight_layout(self) -> None:
        return None

    def savefig(self, output_path: Path, dpi: int, bbox_inches: str) -> None:
        _ = (output_path, dpi, bbox_inches)


class _FakePyplot:
    """Minimal pyplot stub with subplot and close support."""

    def subplots(self, figsize: tuple[float, float]) -> tuple[_FakeFigure, _FakeAxis]:
        _ = figsize
        return _FakeFigure(), _FakeAxis()

    def close(self, figure: object) -> None:
        _ = figure


class EvaluationPlotsTestCase(unittest.TestCase):
    """Validate JSON and plot artifact generation for model training."""

    def test_save_training_evaluation_artifacts_creates_expected_outputs(self) -> None:
        """Save metrics JSON and simple chart artifacts for a training run."""
        evaluation_results = {
            "logistic_regression": {
                "accuracy": 0.61,
                "precision": 0.60,
                "recall": 0.61,
                "f1_score": 0.60,
                "classification_report": "logistic report",
            },
            "random_forest": {
                "accuracy": 0.91,
                "precision": 0.90,
                "recall": 0.89,
                "f1_score": 0.90,
                "classification_report": "random forest report",
            },
        }

        written_files: dict[str, str] = {}

        def fake_write_text(self: Path, content: str, encoding: str = "utf-8") -> int:
            _ = encoding
            written_files[str(self)] = content
            return len(content)

        with patch(
            "src.ml.evaluation_plots._load_plot_dependencies",
            return_value=(_FakePyplot(), lambda y_true, y_pred, labels: [[1, 0], [0, 1]]),
        ), patch(
            "src.ml.evaluation_plots.Path.write_text",
            new=fake_write_text,
        ):
            artifact_paths = save_training_evaluation_artifacts(
                evaluation_results=evaluation_results,
                best_model_name="random_forest",
                best_model=_FakeModel(),
                x_test=object(),
                y_test=_FakeSeries(["benign", "malicious"]),
                output_dir="models/reports",
            )

        metrics_summary_path = artifact_paths["metrics_summary_path"]
        metrics_payload = written_files[metrics_summary_path]

        self.assertIn('"best_model_name": "random_forest"', metrics_payload)
        self.assertIn('"recommended_baseline": "random_forest"', metrics_payload)
        self.assertTrue(metrics_summary_path.endswith("metrics_summary.json"))
        self.assertTrue(
            artifact_paths["confusion_matrix_path"].endswith("best_model_confusion_matrix.png")
        )
        self.assertTrue(
            artifact_paths["model_comparison_path"].endswith("model_f1_comparison.png")
        )


if __name__ == "__main__":
    unittest.main()
