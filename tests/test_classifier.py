"""Tests for the baseline machine learning pipeline."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ml.classifier import (
    DatasetFormatError,
    MalwareClassifier,
    MLClassifierError,
    ModelNotLoadedError,
    get_class_distribution,
    get_dataset_row_count,
    load_csv_dataset,
    load_saved_model,
    predict_with_saved_model,
    select_best_model,
    split_features_and_target,
    train_from_csv,
)


class FakeSeries:
    """Small stand-in for a pandas Series."""

    def __init__(self, values: list[object]) -> None:
        self.values = values

    def tolist(self) -> list[object]:
        """Return the contained values as a plain list."""
        return list(self.values)


class FakeDataFrame:
    """Small stand-in for a pandas DataFrame."""

    def __init__(self, rows: list[dict[str, object]], columns: list[str] | None = None) -> None:
        self.rows = rows
        self.columns = columns or (list(rows[0].keys()) if rows else [])

    def drop(self, columns: list[str]) -> "FakeDataFrame":
        """Return a new frame with selected columns removed."""
        remaining = [column for column in self.columns if column not in columns]
        new_rows = [
            {column: row[column] for column in remaining}
            for row in self.rows
        ]
        return FakeDataFrame(new_rows, columns=remaining)

    def __getitem__(self, key: str) -> FakeSeries:
        """Return a fake series for the requested column."""
        return FakeSeries([row[key] for row in self.rows])


class FakeTrainedModel:
    """Small fake estimator with deterministic behavior."""

    def __init__(self, name: str, predictions: list[str], probabilities: list[list[float]]) -> None:
        self.name = name
        self.predictions = predictions
        self.probabilities = probabilities
        self.classes_ = ["benign", "malicious"]

    def fit(self, x_train: object, y_train: object) -> "FakeTrainedModel":
        """Return self to mirror scikit-learn estimators."""
        _ = (x_train, y_train)
        return self

    def predict(self, x_input: object) -> list[str]:
        """Return deterministic predictions."""
        _ = x_input
        return self.predictions

    def predict_proba(self, x_input: object) -> list[list[float]]:
        """Return deterministic class probabilities."""
        _ = x_input
        return self.probabilities


class FakePandasModule:
    """Minimal pandas-like object for the classifier tests."""

    def __init__(self, dataset: FakeDataFrame) -> None:
        self.dataset = dataset
        self.read_csv = MagicMock(return_value=dataset)
        self.DataFrame = lambda rows, columns=None: FakeDataFrame(rows, columns=columns)


class ClassifierModuleTestCase(unittest.TestCase):
    """Validate the baseline ML helpers with synthetic data and fake dependencies."""

    def setUp(self) -> None:
        """Create reusable synthetic dataset fixtures."""
        self.dataset = FakeDataFrame(
            rows=[
                {
                    "file_size": 1000,
                    "page_count": 1,
                    "metadata_field_count": 2,
                    "suspicious_keyword_total": 0,
                    "is_encrypted": 0,
                    "high_risk_keyword_total": 0,
                    "keyword_density_per_page": 0.0,
                    "has_javascript": 0,
                    "label": "benign",
                },
                {
                    "file_size": 2000,
                    "page_count": 2,
                    "metadata_field_count": 1,
                    "suspicious_keyword_total": 3,
                    "is_encrypted": 0,
                    "high_risk_keyword_total": 2,
                    "keyword_density_per_page": 1.5,
                    "has_javascript": 1,
                    "label": "malicious",
                },
                {
                    "file_size": 1500,
                    "page_count": 1,
                    "metadata_field_count": 0,
                    "suspicious_keyword_total": 2,
                    "is_encrypted": 0,
                    "high_risk_keyword_total": 1,
                    "keyword_density_per_page": 2.0,
                    "has_javascript": 1,
                    "label": "suspicious",
                },
                {
                    "file_size": 900,
                    "page_count": 1,
                    "metadata_field_count": 3,
                    "suspicious_keyword_total": 0,
                    "is_encrypted": 0,
                    "high_risk_keyword_total": 0,
                    "keyword_density_per_page": 0.0,
                    "has_javascript": 0,
                    "label": "benign",
                },
            ]
        )

    def test_load_csv_dataset_uses_pandas_reader(self) -> None:
        """Load a CSV path through the pandas dependency."""
        fake_dependencies = MagicMock()
        fake_dependencies.pandas.read_csv.return_value = self.dataset

        with patch("src.ml.classifier.Path.is_file", return_value=True), patch(
            "src.ml.classifier._load_dependencies",
            return_value=fake_dependencies,
        ):
            dataset = load_csv_dataset("data/features.csv")

        self.assertIs(dataset, self.dataset)
        fake_dependencies.pandas.read_csv.assert_called_once()

    def test_split_features_and_target_separates_label_column(self) -> None:
        """Separate feature columns and labels cleanly."""
        features, labels = split_features_and_target(self.dataset)

        self.assertEqual(
            features.columns,
            [
                "file_size",
                "page_count",
                "metadata_field_count",
                "suspicious_keyword_total",
                "is_encrypted",
                "high_risk_keyword_total",
                "keyword_density_per_page",
                "has_javascript",
            ],
        )
        self.assertEqual(labels.tolist(), ["benign", "malicious", "suspicious", "benign"])

    def test_load_csv_dataset_raises_friendly_error_for_malformed_csv(self) -> None:
        """Wrap CSV parsing failures in a readable dataset format error."""
        fake_dependencies = MagicMock()
        fake_dependencies.pandas.read_csv.side_effect = ValueError("bad csv")

        with patch("src.ml.classifier.Path.is_file", return_value=True), patch(
            "src.ml.classifier._load_dependencies",
            return_value=fake_dependencies,
        ), self.assertRaises(DatasetFormatError) as context:
            load_csv_dataset("data/bad.csv")

        self.assertIn("Unable to read dataset CSV", str(context.exception))

    def test_split_features_and_target_raises_for_missing_expected_columns(self) -> None:
        """Require the expected training feature columns for a clean retraining workflow."""
        incomplete_dataset = FakeDataFrame(
            rows=[
                {
                    "file_size": 1000,
                    "page_count": 1,
                    "label": "benign",
                }
            ]
        )

        with self.assertRaises(DatasetFormatError) as context:
            split_features_and_target(incomplete_dataset)

        self.assertIn("missing expected feature columns", str(context.exception).lower())

    def test_select_best_model_prefers_random_forest_on_metric_tie(self) -> None:
        """Prefer Random Forest when competing models share the same score."""
        trained_models = {
            "random_forest": object(),
            "gradient_boosting": object(),
        }
        metrics = {
            "random_forest": {"f1_score": 0.80, "accuracy": 0.75},
            "gradient_boosting": {"f1_score": 0.80, "accuracy": 0.75},
        }

        model_name, model, best_metrics = select_best_model(trained_models, metrics)

        self.assertEqual(model_name, "random_forest")
        self.assertIs(model, trained_models["random_forest"])
        self.assertEqual(best_metrics["f1_score"], 0.80)

    def test_train_from_csv_trains_evaluates_and_saves_best_model(self) -> None:
        """Run the full training pipeline with a synthetic dataset."""
        fake_pandas = FakePandasModule(self.dataset)
        fake_joblib = MagicMock()
        fake_dependencies = MagicMock()
        fake_dependencies.pandas = fake_pandas
        fake_dependencies.joblib = fake_joblib
        fake_dependencies.train_test_split.return_value = (
            FakeDataFrame(
                self.dataset.rows[:3],
                columns=[
                    "file_size",
                    "page_count",
                    "metadata_field_count",
                    "suspicious_keyword_total",
                    "is_encrypted",
                    "high_risk_keyword_total",
                    "keyword_density_per_page",
                    "has_javascript",
                ],
            ),
            FakeDataFrame(
                self.dataset.rows[3:],
                columns=[
                    "file_size",
                    "page_count",
                    "metadata_field_count",
                    "suspicious_keyword_total",
                    "is_encrypted",
                    "high_risk_keyword_total",
                    "keyword_density_per_page",
                    "has_javascript",
                ],
            ),
            FakeSeries(["benign", "malicious", "suspicious"]),
            FakeSeries(["benign"]),
        )
        fake_dependencies.accuracy_score.side_effect = [0.60, 0.90, 0.70]
        fake_dependencies.precision_recall_fscore_support.side_effect = [
            (0.55, 0.60, 0.58, None),
            (0.88, 0.90, 0.89, None),
            (0.68, 0.70, 0.69, None),
        ]
        fake_dependencies.classification_report.side_effect = [
            "logistic report",
            "random forest report",
            "gradient boosting report",
        ]
        fake_dependencies.LogisticRegression.return_value = FakeTrainedModel(
            "logistic_regression",
            predictions=["benign"],
            probabilities=[[0.70, 0.30]],
        )
        fake_dependencies.RandomForestClassifier.return_value = FakeTrainedModel(
            "random_forest",
            predictions=["benign"],
            probabilities=[[0.80, 0.20]],
        )
        fake_dependencies.GradientBoostingClassifier.return_value = FakeTrainedModel(
            "gradient_boosting",
            predictions=["malicious"],
            probabilities=[[0.20, 0.80]],
        )

        written_json: dict[str, str] = {}

        def fake_write_text(self: Path, content: str, encoding: str = "utf-8") -> int:
            _ = encoding
            written_json[str(self)] = content
            return len(content)

        with patch("src.ml.classifier.Path.is_file", return_value=True), patch(
            "src.ml.classifier._load_dependencies",
            return_value=fake_dependencies,
        ), patch("src.ml.classifier.Path.mkdir"), patch(
            "src.ml.classifier.Path.write_text",
            new=fake_write_text,
        ), patch(
            "src.ml.evaluation_plots.save_training_evaluation_artifacts",
            return_value={
                "reports_dir": "models/reports",
                "metrics_summary_path": "models/reports/metrics_summary.json",
                "confusion_matrix_path": "models/reports/best_model_confusion_matrix.png",
                "model_comparison_path": "models/reports/model_f1_comparison.png",
            },
        ):
            result = train_from_csv(
                "data/features.csv",
                model_dir="models",
            )

        self.assertEqual(result["recommended_baseline"], "random_forest")
        self.assertEqual(result["best_model_name"], "random_forest")
        self.assertEqual(result["dataset_row_count"], 4)
        self.assertEqual(result["class_distribution"], {"benign": 2, "malicious": 1, "suspicious": 1})
        self.assertEqual(result["best_model_metrics"]["f1_score"], 0.89)
        self.assertEqual(
            result["feature_columns"],
            [
                "file_size",
                "page_count",
                "metadata_field_count",
                "suspicious_keyword_total",
                "is_encrypted",
                "high_risk_keyword_total",
                "keyword_density_per_page",
                "has_javascript",
            ],
        )
        self.assertTrue(result["model_path"].endswith("best_model.joblib"))
        self.assertTrue(result["feature_columns_path"].endswith("feature_columns.json"))
        self.assertTrue(result["metrics_summary_path"].endswith("metrics_summary.json"))
        self.assertTrue(result["confusion_matrix_path"].endswith("best_model_confusion_matrix.png"))
        self.assertTrue(result["model_comparison_path"].endswith("model_f1_comparison.png"))
        self.assertTrue(written_json[result["feature_columns_path"]])
        fake_joblib.dump.assert_called_once()

    def test_dataset_summary_helpers_return_row_count_and_class_distribution(self) -> None:
        """Return simple dataset-level summary values for CLI output."""
        labels = FakeSeries(["benign", "malicious", "benign"])

        self.assertEqual(get_dataset_row_count(self.dataset), 4)
        self.assertEqual(get_class_distribution(labels), {"benign": 2, "malicious": 1})

    def test_loaded_classifier_predicts_with_feature_alignment(self) -> None:
        """Load saved artifacts and predict from a flat feature dictionary."""
        fake_pandas = MagicMock()
        captured_rows: list[dict[str, object]] = []

        def build_frame(rows: list[dict[str, object]], columns: list[str] | None = None) -> FakeDataFrame:
            captured_rows.extend(rows)
            return FakeDataFrame(rows, columns=columns)

        fake_pandas.DataFrame = build_frame
        fake_joblib = MagicMock()
        fake_model = FakeTrainedModel(
            "random_forest",
            predictions=["malicious"],
            probabilities=[[0.15, 0.85]],
        )
        fake_joblib.load.return_value = fake_model
        fake_dependencies = MagicMock()
        fake_dependencies.pandas = fake_pandas
        fake_dependencies.joblib = fake_joblib

        feature_columns_payload = json.dumps(["file_size", "page_count", "has_javascript"])

        with patch("src.ml.classifier.Path.is_file", return_value=True), patch(
            "src.ml.classifier.Path.read_text",
            return_value=feature_columns_payload,
        ), patch(
            "src.ml.classifier._load_dependencies",
            return_value=fake_dependencies,
        ):
            classifier = MalwareClassifier.load(
                "models/best_model.joblib",
                "models/feature_columns.json",
            )
            result = classifier.predict(
                {
                    "file_size": 5000,
                    "page_count": 3,
                    "has_javascript": True,
                    "unused_feature": 99,
                }
            )

        self.assertEqual(result.label, "malicious")
        self.assertEqual(result.confidence, 0.85)
        self.assertEqual(result.probabilities, {"benign": 0.15, "malicious": 0.85})
        self.assertEqual(
            captured_rows[0],
            {"file_size": 5000.0, "page_count": 3.0, "has_javascript": 1.0},
        )

    def test_predict_raises_when_model_is_not_loaded(self) -> None:
        """Guard against prediction before loading model artifacts."""
        classifier = MalwareClassifier()
        with self.assertRaises(ModelNotLoadedError):
            classifier.predict({"file_size": 1000})

    def test_predict_raises_for_invalid_feature_input(self) -> None:
        """Reject non-dictionary feature payloads cleanly."""
        classifier = MalwareClassifier(model=object(), feature_columns=["file_size"])
        with self.assertRaises(MLClassifierError):
            classifier.predict(["not", "a", "dict"])  # type: ignore[arg-type]

    def test_load_saved_model_uses_default_model_paths(self) -> None:
        """Load a classifier from the default models directory."""
        with patch("src.ml.classifier.MalwareClassifier.load", return_value=MagicMock()) as load_mock:
            classifier = load_saved_model(model_dir="models")

        self.assertIsNotNone(classifier)
        load_mock.assert_called_once()
        model_path = str(load_mock.call_args.args[0])
        feature_columns_path = str(load_mock.call_args.args[1])
        self.assertTrue(model_path.endswith("models\\best_model.joblib") or model_path.endswith("models/best_model.joblib"))
        self.assertTrue(feature_columns_path.endswith("models\\feature_columns.json") or feature_columns_path.endswith("models/feature_columns.json"))

    def test_predict_with_saved_model_returns_expected_dictionary(self) -> None:
        """Load artifacts and return a simple prediction dictionary."""
        fake_result = MagicMock(
            predicted_label="suspicious",
            confidence=0.61,
            class_probabilities={"benign": 0.39, "suspicious": 0.61},
        )
        fake_classifier = MagicMock()
        fake_classifier.predict.return_value = fake_result

        with patch("src.ml.classifier.load_saved_model", return_value=fake_classifier):
            result = predict_with_saved_model({"file_size": 1200}, model_dir="models")

        self.assertEqual(result["predicted_label"], "suspicious")
        self.assertEqual(result["confidence"], 0.61)
        self.assertEqual(result["class_probabilities"]["suspicious"], 0.61)


if __name__ == "__main__":
    unittest.main()
