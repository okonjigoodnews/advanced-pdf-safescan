"""Baseline machine learning training and prediction helpers for PDF features."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any

from src.features.extractor import FeatureVector
from src.utils.paths import project_root


DEFAULT_TARGET_COLUMN = "label"
DEFAULT_MODEL_FILENAME = "best_model.joblib"
DEFAULT_FEATURE_COLUMNS_FILENAME = "feature_columns.json"
DEFAULT_REPORTS_DIRNAME = "reports"
DEFAULT_TEST_SIZE = 0.2
DEFAULT_RANDOM_STATE = 42
MODEL_PRIORITY = {
    "random_forest": 0,
    "gradient_boosting": 1,
    "logistic_regression": 2,
}
EXPECTED_FEATURE_COLUMNS = [
    "file_size",
    "page_count",
    "metadata_field_count",
    "suspicious_keyword_total",
    "is_encrypted",
    "high_risk_keyword_total",
    "keyword_density_per_page",
    "has_javascript",
]

EvaluationMetrics = dict[str, Any]


class MLClassifierError(Exception):
    """Base exception for machine learning pipeline failures."""


class MLDependencyError(MLClassifierError):
    """Raised when required third-party ML dependencies are unavailable."""


class DatasetFormatError(MLClassifierError):
    """Raised when the input dataset does not match the expected format."""


class ModelNotLoadedError(MLClassifierError):
    """Raised when prediction is attempted before a model is loaded."""


@dataclass(slots=True)
class MLResult:
    """Prediction result returned by the baseline classifier."""

    predicted_label: str
    confidence: float
    class_probabilities: dict[str, float] | None = None

    @property
    def label(self) -> str:
        """Backward-compatible alias for the predicted label."""
        return self.predicted_label

    @property
    def probabilities(self) -> dict[str, float] | None:
        """Backward-compatible alias for class probabilities."""
        return self.class_probabilities


@dataclass(frozen=True, slots=True)
class DependencyBundle:
    """Lazy-loaded third-party dependencies used by the ML pipeline."""

    pandas: Any
    joblib: Any
    train_test_split: Any
    accuracy_score: Any
    precision_recall_fscore_support: Any
    classification_report: Any
    LogisticRegression: Any
    RandomForestClassifier: Any
    GradientBoostingClassifier: Any


def load_csv_dataset(csv_path: str | Path) -> Any:
    """Load a labeled feature dataset from CSV using pandas."""
    path = Path(csv_path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    dependencies = _load_dependencies()
    try:
        return dependencies.pandas.read_csv(path, low_memory=False)
    except Exception as exc:
        raise DatasetFormatError(f"Unable to read dataset CSV: {path}") from exc


def split_features_and_target(dataset: Any, target_column: str = DEFAULT_TARGET_COLUMN) -> tuple[Any, Any]:
    """Separate a tabular dataset into feature columns and target labels."""
    columns = list(getattr(dataset, "columns", []))
    if target_column not in columns:
        raise DatasetFormatError(
            f"Target column '{target_column}' was not found in the dataset."
        )

    feature_frame = dataset.drop(columns=[target_column])
    feature_columns = list(getattr(feature_frame, "columns", []))

    if not feature_columns:
        raise DatasetFormatError("Dataset must contain at least one feature column.")

    missing_expected_columns = [
        column for column in EXPECTED_FEATURE_COLUMNS
        if column not in feature_columns
    ]
    if missing_expected_columns:
        raise DatasetFormatError(
            "Dataset is missing expected feature columns: "
            + ", ".join(missing_expected_columns)
        )

    feature_frame = prepare_feature_frame(feature_frame)
    target_series = dataset[target_column]
    return feature_frame, target_series


def prepare_feature_frame(feature_frame: Any) -> Any:
    """Coerce training feature columns to numeric values for more stable training."""
    if not hasattr(feature_frame, "apply"):
        return feature_frame

    dependencies = _load_dependencies()
    try:
        numeric_frame = feature_frame.apply(dependencies.pandas.to_numeric, errors="coerce")
        if hasattr(numeric_frame, "fillna"):
            numeric_frame = numeric_frame.fillna(0.0)
        return numeric_frame
    except Exception as exc:
        raise DatasetFormatError("Feature columns could not be converted into numeric values.") from exc


def get_dataset_row_count(dataset: Any) -> int:
    """Return the number of rows in the dataset."""
    if hasattr(dataset, "__len__"):
        return int(len(dataset))
    rows = getattr(dataset, "rows", None)
    if rows is not None:
        return int(len(rows))
    return 0


def get_class_distribution(labels: Any) -> dict[str, int]:
    """Return simple label counts for training summary output."""
    counts: dict[str, int] = {}
    for label in _to_python_list(labels):
        normalized_label = str(label)
        counts[normalized_label] = counts.get(normalized_label, 0) + 1
    return counts


def train_test_data_split(
    features: Any,
    labels: Any,
    *,
    test_size: float = DEFAULT_TEST_SIZE,
    random_state: int = DEFAULT_RANDOM_STATE,
) -> tuple[Any, Any, Any, Any]:
    """Split features and labels into train and test partitions."""
    dependencies = _load_dependencies()
    try:
        unique_label_count = len(set(_to_python_list(labels)))
    except TypeError:
        unique_label_count = 0

    stratify_labels = labels if unique_label_count > 1 else None
    try:
        return dependencies.train_test_split(
            features,
            labels,
            test_size=test_size,
            random_state=random_state,
            stratify=stratify_labels,
        )
    except Exception as exc:
        raise DatasetFormatError("Unable to split the dataset into train and test sets.") from exc


def train_candidate_models(
    x_train: Any,
    y_train: Any,
    *,
    random_state: int = DEFAULT_RANDOM_STATE,
) -> dict[str, Any]:
    """Train the baseline candidate models and return them by name."""
    dependencies = _load_dependencies()
    candidates = {
        "logistic_regression": dependencies.LogisticRegression(
            max_iter=1000,
            random_state=random_state,
        ),
        "random_forest": dependencies.RandomForestClassifier(
            n_estimators=200,
            random_state=random_state,
            n_jobs=-1,
        ),
        "gradient_boosting": dependencies.GradientBoostingClassifier(
            random_state=random_state,
        ),
    }

    trained_models: dict[str, Any] = {}
    for model_name, model in candidates.items():
        try:
            trained_models[model_name] = model.fit(x_train, y_train)
        except Exception as exc:
            raise MLClassifierError(f"Training failed for model '{model_name}'.") from exc
    return trained_models


def evaluate_model(model: Any, x_test: Any, y_test: Any) -> EvaluationMetrics:
    """Evaluate a trained model and return standard classification metrics."""
    dependencies = _load_dependencies()
    try:
        predictions = model.predict(x_test)
        precision, recall, f1_score, _ = dependencies.precision_recall_fscore_support(
            y_test,
            predictions,
            average="weighted",
            zero_division=0,
        )
        return {
            "accuracy": float(dependencies.accuracy_score(y_test, predictions)),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1_score),
            "classification_report": str(
                dependencies.classification_report(
                    y_test,
                    predictions,
                    zero_division=0,
                )
            ),
        }
    except Exception as exc:
        raise MLClassifierError("Model evaluation failed.") from exc


def evaluate_models(models: dict[str, Any], x_test: Any, y_test: Any) -> dict[str, EvaluationMetrics]:
    """Evaluate a set of trained models and return metrics by model name."""
    return {
        model_name: evaluate_model(model, x_test, y_test)
        for model_name, model in models.items()
    }


def select_best_model(
    trained_models: dict[str, Any],
    evaluation_results: dict[str, EvaluationMetrics],
) -> tuple[str, Any, EvaluationMetrics]:
    """Select the best model, preferring Random Forest when scores are tied."""
    if not trained_models:
        raise MLClassifierError("No trained models were provided for selection.")

    def model_rank(item: tuple[str, EvaluationMetrics]) -> tuple[float, float, int]:
        model_name, metrics = item
        return (
            float(metrics.get("f1_score", 0.0)),
            float(metrics.get("accuracy", 0.0)),
            -MODEL_PRIORITY.get(model_name, 99),
        )

    best_model_name, best_metrics = max(evaluation_results.items(), key=model_rank)
    return best_model_name, trained_models[best_model_name], best_metrics


def save_best_model(
    model: Any,
    feature_columns: list[str],
    *,
    model_dir: str | Path | None = None,
    model_filename: str = DEFAULT_MODEL_FILENAME,
    feature_columns_filename: str = DEFAULT_FEATURE_COLUMNS_FILENAME,
) -> dict[str, str]:
    """Save a trained model and its feature column order into the models directory."""
    dependencies = _load_dependencies()
    output_dir = _resolve_model_dir(model_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / model_filename
    feature_columns_path = output_dir / feature_columns_filename

    try:
        dependencies.joblib.dump(model, model_path)
        feature_columns_path.write_text(
            json.dumps(feature_columns, indent=2),
            encoding="utf-8",
        )
    except Exception as exc:
        raise MLClassifierError("Failed to save model artifacts.") from exc

    return {
        "model_path": str(model_path),
        "feature_columns_path": str(feature_columns_path),
    }


def load_saved_model(
    *,
    model_dir: str | Path | None = None,
    model_filename: str = DEFAULT_MODEL_FILENAME,
    feature_columns_filename: str = DEFAULT_FEATURE_COLUMNS_FILENAME,
) -> MalwareClassifier:
    """Load the saved baseline model and feature ordering from the models directory."""
    model_path, feature_columns_path = resolve_model_artifact_paths(
        model_dir=model_dir,
        model_filename=model_filename,
        feature_columns_filename=feature_columns_filename,
    )
    return MalwareClassifier.load(model_path, feature_columns_path)


def predict_with_saved_model(
    features: FeatureVector,
    *,
    model_dir: str | Path | None = None,
    model_filename: str = DEFAULT_MODEL_FILENAME,
    feature_columns_filename: str = DEFAULT_FEATURE_COLUMNS_FILENAME,
) -> dict[str, Any]:
    """Load the saved model, align one feature dictionary, and return prediction output."""
    classifier = load_saved_model(
        model_dir=model_dir,
        model_filename=model_filename,
        feature_columns_filename=feature_columns_filename,
    )
    result = classifier.predict(features)
    return {
        "predicted_label": result.predicted_label,
        "confidence": result.confidence,
        "class_probabilities": result.class_probabilities,
    }


def load_feature_columns(feature_columns_path: str | Path) -> list[str]:
    """Load feature column ordering from the saved JSON artifact."""
    path = Path(feature_columns_path)
    if not path.is_file():
        raise FileNotFoundError(f"Feature columns file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise MLClassifierError("Unable to read feature columns metadata.") from exc

    if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
        raise MLClassifierError("Feature columns metadata must be a list of strings.")
    return data


def train_from_csv(
    csv_path: str | Path,
    *,
    target_column: str = DEFAULT_TARGET_COLUMN,
    test_size: float = DEFAULT_TEST_SIZE,
    random_state: int = DEFAULT_RANDOM_STATE,
    model_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Train baseline models from a CSV dataset and save the best model artifacts."""
    from src.ml.evaluation_plots import save_training_evaluation_artifacts

    dataset = load_csv_dataset(csv_path)
    features, labels = split_features_and_target(dataset, target_column=target_column)
    dataset_row_count = get_dataset_row_count(dataset)
    class_distribution = get_class_distribution(labels)

    x_train, x_test, y_train, y_test = train_test_data_split(
        features,
        labels,
        test_size=test_size,
        random_state=random_state,
    )
    trained_models = train_candidate_models(
        x_train,
        y_train,
        random_state=random_state,
    )
    evaluation_results = evaluate_models(trained_models, x_test, y_test)
    best_model_name, best_model, best_metrics = select_best_model(
        trained_models,
        evaluation_results,
    )
    artifact_paths = save_best_model(
        best_model,
        feature_columns=list(getattr(features, "columns", [])),
        model_dir=model_dir,
    )
    report_paths = save_training_evaluation_artifacts(
        evaluation_results=evaluation_results,
        best_model_name=best_model_name,
        best_model=best_model,
        x_test=x_test,
        y_test=y_test,
        output_dir=_resolve_report_dir(model_dir),
    )

    return {
        "dataset_row_count": dataset_row_count,
        "class_distribution": class_distribution,
        "target_column": target_column,
        "best_model_name": best_model_name,
        "recommended_baseline": "random_forest",
        "best_model_metrics": best_metrics,
        "all_model_metrics": evaluation_results,
        "feature_columns": list(getattr(features, "columns", [])),
        **artifact_paths,
        **report_paths,
    }


class MalwareClassifier:
    """Load a trained model and predict labels for extracted PDF features."""

    def __init__(self, model: Any | None = None, feature_columns: list[str] | None = None) -> None:
        """Create a classifier wrapper around a trained model artifact."""
        self.model = model
        self.feature_columns = feature_columns or []

    @classmethod
    def load(
        cls,
        model_path: str | Path,
        feature_columns_path: str | Path,
    ) -> MalwareClassifier:
        """Load a saved model and its feature ordering from disk."""
        dependencies = _load_dependencies()
        model_file = Path(model_path)
        if not model_file.is_file():
            raise FileNotFoundError(
                f"Model file not found: {model_file}. Train the model first or check --model-dir."
            )

        try:
            model = dependencies.joblib.load(model_file)
        except Exception as exc:
            raise MLClassifierError("Unable to load the saved model artifact.") from exc

        feature_columns = load_feature_columns(feature_columns_path)
        return cls(model=model, feature_columns=feature_columns)

    def predict(self, features: FeatureVector) -> MLResult:
        """Predict a label and confidence score from a single feature dictionary."""
        if self.model is None or not self.feature_columns:
            raise ModelNotLoadedError("Load a trained model before calling predict().")
        if not isinstance(features, dict):
            raise MLClassifierError("Input features must be provided as a dictionary.")

        dependencies = _load_dependencies()
        row = self.align_features(features)
        try:
            frame = dependencies.pandas.DataFrame([row], columns=self.feature_columns)
            predicted_label = str(self.model.predict(frame)[0])
            probabilities = self._predict_probabilities(frame)
        except Exception as exc:
            raise MLClassifierError("Prediction failed for the provided feature dictionary.") from exc

        confidence = max(probabilities.values()) if probabilities else 0.0
        return MLResult(
            predicted_label=predicted_label,
            confidence=confidence,
            class_probabilities=probabilities or None,
        )

    def align_features(self, features: FeatureVector) -> dict[str, float]:
        """Align incoming features to the saved training column order."""
        if not isinstance(features, dict):
            raise MLClassifierError("Input features must be provided as a dictionary.")
        return {
            column: self._coerce_feature_value(features.get(column, 0))
            for column in self.feature_columns
        }

    def _predict_probabilities(self, frame: Any) -> dict[str, float]:
        """Return class probabilities when the loaded model supports them."""
        if not hasattr(self.model, "predict_proba"):
            return {}

        probabilities = self.model.predict_proba(frame)[0]
        class_names = [str(label) for label in getattr(self.model, "classes_", [])]
        if not class_names:
            return {}
        return {
            class_name: float(probability)
            for class_name, probability in zip(class_names, probabilities)
        }

    def _coerce_feature_value(self, value: object) -> float:
        """Convert incoming feature values into numeric model inputs."""
        if isinstance(value, bool):
            return float(int(value))
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0


def _load_dependencies() -> DependencyBundle:
    """Import third-party ML dependencies lazily so the module stays import-safe."""
    try:
        pandas_module = import_module("pandas")
        joblib_module = import_module("joblib")
        model_selection = import_module("sklearn.model_selection")
        metrics_module = import_module("sklearn.metrics")
        linear_model = import_module("sklearn.linear_model")
        ensemble_module = import_module("sklearn.ensemble")
    except ImportError as exc:
        raise MLDependencyError(
            "pandas, scikit-learn, and joblib are required for the ML pipeline."
        ) from exc

    return DependencyBundle(
        pandas=pandas_module,
        joblib=joblib_module,
        train_test_split=model_selection.train_test_split,
        accuracy_score=metrics_module.accuracy_score,
        precision_recall_fscore_support=metrics_module.precision_recall_fscore_support,
        classification_report=metrics_module.classification_report,
        LogisticRegression=linear_model.LogisticRegression,
        RandomForestClassifier=ensemble_module.RandomForestClassifier,
        GradientBoostingClassifier=ensemble_module.GradientBoostingClassifier,
    )


def _to_python_list(values: Any) -> list[Any]:
    """Convert a vector-like object into a Python list."""
    if hasattr(values, "tolist"):
        return list(values.tolist())
    return list(values)


def resolve_model_artifact_paths(
    *,
    model_dir: str | Path | None = None,
    model_filename: str = DEFAULT_MODEL_FILENAME,
    feature_columns_filename: str = DEFAULT_FEATURE_COLUMNS_FILENAME,
) -> tuple[Path, Path]:
    """Resolve saved model artifact locations from the models directory."""
    base_dir = _resolve_model_dir(model_dir)
    return base_dir / model_filename, base_dir / feature_columns_filename


def _resolve_model_dir(model_dir: str | Path | None) -> Path:
    """Return the directory used for model artifacts."""
    return Path(model_dir) if model_dir is not None else project_root() / "models"


def _resolve_report_dir(model_dir: str | Path | None) -> Path:
    """Return the directory used for training report artifacts."""
    return _resolve_model_dir(model_dir) / DEFAULT_REPORTS_DIRNAME
