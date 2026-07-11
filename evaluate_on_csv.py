#!/usr/bin/env python3
"""
========================================================================
PDFSafeScan Evaluation on the Feature CSV
========================================================================
Evaluates the Logistic Regression model using the already-extracted
features in data/features/train.csv.

It performs an 80/20 stratified split (matching the project's own
settings), trains on 80 percent, and evaluates on the held-out 20
percent that the model never saw. This gives real, defensible metrics.

WHAT IT PRODUCES:
    1. Printed metrics in the terminal
    2. metrics.txt          : the full results, ready to paste
    3. confusion_matrix.png : a visual chart for the Results chapter

HOW TO RUN (from the project root, with your .venv active):
    python evaluate_on_csv.py

If matplotlib is not installed:
    pip install scikit-learn pandas matplotlib
========================================================================
"""

import time
import warnings
from pathlib import Path

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

warnings.filterwarnings("ignore")

# ---- Settings that match the project ----
CSV_PATH = "data/features/train.csv"
TEST_SIZE = 0.2          # 80/20 split, matches DEFAULT_TEST_SIZE
RANDOM_STATE = 42        # fixed for reproducibility
LABEL_COLUMN = "label"


def main():
    print("=" * 60)
    print("PDFSafeScan Evaluation (held-out 20 percent)")
    print("=" * 60)

    # Load the feature data
    path = Path(CSV_PATH)
    if not path.exists():
        print(f"ERROR: could not find {CSV_PATH}. Run from the project root.")
        return
    df = pd.read_csv(path)
    print(f"\nLoaded {len(df)} rows from {CSV_PATH}")

    # Separate features (X) and label (y)
    y_raw = df[LABEL_COLUMN].astype(str).str.strip().str.lower()
    y = (y_raw == "malicious").astype(int)   # 1 = malicious, 0 = benign
    X = df.drop(columns=[LABEL_COLUMN])

    # Convert any True/False columns to 1/0
    X = X.replace({True: 1, False: 0})
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

    print(f"Malicious files: {int(y.sum())}")
    print(f"Benign files:    {int((y == 0).sum())}")
    print(f"Total features:  {X.shape[1]}")

    # 80/20 stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\nTraining on {len(X_train)} files, testing on {len(X_test)} held-out files.")

    # Scale features (helps Logistic Regression converge)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train the Logistic Regression model
    model = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)
    model.fit(X_train_scaled, y_train)

    # Predict on the held-out test set, timing it
    start = time.time()
    y_pred = model.predict(X_test_scaled)
    elapsed = time.time() - start
    avg_ms = (elapsed / len(X_test)) * 1000 if len(X_test) else 0.0

    # Metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    lines = []
    lines.append("PDFSafeScan Evaluation Metrics (held-out 20 percent)")
    lines.append("=" * 50)
    lines.append(f"Total dataset size : {len(df)}")
    lines.append(f"Training files     : {len(X_train)}")
    lines.append(f"Test files (unseen): {len(X_test)}")
    lines.append("")
    lines.append(f"Accuracy           : {acc:.4f}  ({acc*100:.2f}%)")
    lines.append(f"Precision          : {prec:.4f}")
    lines.append(f"Recall             : {rec:.4f}")
    lines.append(f"F1-Score           : {f1:.4f}")
    lines.append(f"False Positive Rate: {fpr:.4f}")
    lines.append(f"False Negative Rate: {fnr:.4f}")
    lines.append(f"Avg prediction time: {avg_ms:.4f} ms per file")
    lines.append("")
    lines.append("Confusion Matrix:")
    lines.append(f"  True Positives  (malicious caught) : {tp}")
    lines.append(f"  True Negatives  (benign passed)    : {tn}")
    lines.append(f"  False Positives (benign flagged)   : {fp}")
    lines.append(f"  False Negatives (malicious missed) : {fn}")
    lines.append("")
    lines.append("Classification report:")
    lines.append(classification_report(y_test, y_pred,
                 target_names=["benign", "malicious"], zero_division=0))
    report = "\n".join(lines)

    with open("metrics.txt", "w") as f:
        f.write(report)
    print("\n" + report)
    print("\nSaved metrics.txt")

    # Confusion matrix chart
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.metrics import ConfusionMatrixDisplay
        disp = ConfusionMatrixDisplay(confusion_matrix=cm,
               display_labels=["benign", "malicious"])
        disp.plot(cmap="Blues", values_format="d")
        plt.title("PDFSafeScan Confusion Matrix (held-out test set)")
        plt.tight_layout()
        plt.savefig("confusion_matrix.png", dpi=150)
        print("Saved confusion_matrix.png")
    except Exception as e:
        print(f"(Chart skipped: {e})")

    print("\n" + "=" * 60)
    print("DONE. Paste the contents of metrics.txt back to continue.")
    print("=" * 60)


if __name__ == "__main__":
    main()
