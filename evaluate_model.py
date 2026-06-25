#!/usr/bin/env python3
"""
========================================================================
PDFSafeScan Model Evaluation Script
========================================================================
Evaluates your Contagio-trained model on an UNSEEN test set
(Evasive-PDFMal2022), using your own parser and feature extractor.

PIPELINE (matches your existing code):
    raw PDF
      -> PDFParser.parse()            (counts keywords, reads structure)
      -> PDFFeatureExtractor.extract()(builds your 33 features)
      -> your saved model .predict()  (malicious or benign)
      -> compared against true label

WHAT IT PRODUCES:
    1. results.csv         : one row per PDF (true vs predicted)
    2. metrics.txt         : accuracy, precision, recall, F1, etc.
    3. confusion_matrix.png: visual breakdown of correct vs wrong
    4. Printed summary in the terminal

------------------------------------------------------------------------
BEFORE YOU RUN
------------------------------------------------------------------------
1. Download the RAW PDF files from Evasive-PDFMal2022 (not the CSV).
   Put them in two folders:
       test_data/malicious
       test_data/benign

2. Make sure your trained model file is saved and update MODEL_PATH below
   to point to it (for example models/pdf_model.pkl).

3. Confirm the FEATURE_ORDER list below matches the exact column order
   your model was trained on. THIS IS THE MOST IMPORTANT STEP. If the
   order is wrong, predictions will be meaningless. See the note in that
   section for how to check.

4. Install requirements if needed:
       pip install scikit-learn pandas matplotlib joblib pypdf

5. Run from your project root:
       python evaluate_model.py

------------------------------------------------------------------------
SAFETY: the malicious PDFs are real malware. Run inside a virtual
machine or isolated environment. Never open the files manually.
========================================================================
"""

import csv
import time
import warnings
from pathlib import Path

import joblib
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # no display needed, just save images
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, ConfusionMatrixDisplay, classification_report,
)

# Your own pipeline components
from src.parser.document_parser import PDFParser, PDFParserError
from src.features.extractor import PDFFeatureExtractor

warnings.filterwarnings("ignore")

# ========================================================================
# CONFIGURE THESE
# ========================================================================

# Path to your saved trained model (.pkl or .joblib)
MODEL_PATH = "models/best_model.joblib"

# Folders containing the UNSEEN test PDFs
TEST_FOLDERS = {
    "malicious": Path("test_data/malicious"),
    "benign":    Path("test_data/benign"),
}

# ------------------------------------------------------------------------
# FEATURE_ORDER: the exact list of feature columns, in the exact order,
# that your model was trained on.
#
# HOW TO CHECK THE CORRECT ORDER:
#   If you trained with a pandas DataFrame, the order is the column order
#   of that DataFrame (list(X_train.columns)). Many scikit-learn models
#   also store it in model.feature_names_in_ . You can check by running:
#       import joblib
#       m = joblib.load("models/pdf_model.pkl")
#       print(list(m.feature_names_in_))
#   Then paste that exact list here.
#
# The list below is the COMPLETE set your extractor produces, in a
# sensible default order. Adjust it to match your training order.
# ------------------------------------------------------------------------
FEATURE_ORDER = [
    "file_size",
    "page_count",
    "metadata_field_count",
    "suspicious_keyword_total",
    "is_encrypted",
    "javascript_count", "has_javascript",
    "js_count", "has_js",
    "openaction_count", "has_openaction",
    "aa_count", "has_aa",
    "launch_count", "has_launch",
    "uri_count", "has_uri",
    "embeddedfile_count", "has_embeddedfile",
    "encrypt_count", "has_encrypt",
    "objstm_count", "has_objstm",
    "richmedia_count", "has_richmedia",
    "acroform_count", "has_acroform",
    "action_keyword_total",
    "embedded_or_script_total",
    "stream_like_keyword_total",
    "high_risk_keyword_total",
    "keyword_density_per_page",
]

# How your model encodes its prediction. Many models output 1 for
# malicious and 0 for benign. If yours is reversed, set this to False.
MODEL_OUTPUTS_1_FOR_MALICIOUS = True

# ========================================================================
# You should not need to edit below this line.
# ========================================================================


def build_feature_row(parser, extractor, pdf_path):
    """Run a single PDF through the parser and extractor; return a feature dict."""
    try:
        parsed = parser.parse(pdf_path)
    except PDFParserError:
        # Fall back to raw-byte indicators if full parsing fails
        parsed = parser.read_raw_indicators(pdf_path)
    return extractor.extract(parsed)


def feature_dict_to_ordered_row(features):
    """Return feature values in the exact FEATURE_ORDER the model expects."""
    row = []
    for name in FEATURE_ORDER:
        value = features.get(name, 0)
        # Convert booleans to integers (0 or 1) for the model
        if isinstance(value, bool):
            value = int(value)
        row.append(value)
    return row


def main():
    print("=" * 60)
    print("PDFSafeScan Model Evaluation")
    print("=" * 60)

    # Load the trained model
    print(f"\nLoading model from {MODEL_PATH} ...")
    model = joblib.load(MODEL_PATH)
    print("Model loaded.")

    parser = PDFParser()
    extractor = PDFFeatureExtractor()

    rows = []          # for results.csv
    feature_matrix = []  # for model prediction
    true_labels = []
    file_names = []
    scan_times = []
    skipped = 0

    # Process every PDF in both folders
    for true_label, folder in TEST_FOLDERS.items():
        if not folder.exists():
            print(f"WARNING: folder not found: {folder}")
            continue

        pdf_files = list(folder.glob("*.pdf"))
        print(f"\nProcessing {len(pdf_files)} files in {folder} ...")

        for i, pdf_path in enumerate(pdf_files, 1):
            if i % 500 == 0:
                print(f"  ... {i} files done")
            start = time.time()
            try:
                features = build_feature_row(parser, extractor, pdf_path)
                ordered = feature_dict_to_ordered_row(features)
            except Exception:
                skipped += 1
                continue
            elapsed = time.time() - start

            feature_matrix.append(ordered)
            true_labels.append(1 if true_label == "malicious" else 0)
            file_names.append(pdf_path.name)
            scan_times.append(elapsed)

    if not feature_matrix:
        print("\nNo files were processed. Check your test_data folders.")
        return

    # Run the model on all collected feature rows at once (fast)
    print(f"\nRunning model on {len(feature_matrix)} files ...")
    X = pd.DataFrame(feature_matrix, columns=FEATURE_ORDER)
    raw_predictions = model.predict(X)

    # Normalise predictions to 1 = malicious, 0 = benign
    predictions = []
    for p in raw_predictions:
        p_int = int(p)
        if not MODEL_OUTPUTS_1_FOR_MALICIOUS:
            p_int = 1 - p_int
        predictions.append(p_int)

    # Write results.csv
    with open("results.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "true_label", "predicted_label", "scan_seconds"])
        for name, t, p, s in zip(file_names, true_labels, predictions, scan_times):
            writer.writerow([
                name,
                "malicious" if t == 1 else "benign",
                "malicious" if p == 1 else "benign",
                round(s, 4),
            ])
    print("Saved results.csv")

    # Calculate metrics
    acc = accuracy_score(true_labels, predictions)
    prec = precision_score(true_labels, predictions, zero_division=0)
    rec = recall_score(true_labels, predictions, zero_division=0)
    f1 = f1_score(true_labels, predictions, zero_division=0)
    cm = confusion_matrix(true_labels, predictions)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    avg_time = sum(scan_times) / len(scan_times)

    # Write metrics.txt
    report = []
    report.append("PDFSafeScan Evaluation Metrics")
    report.append("=" * 40)
    report.append(f"Total files tested : {len(true_labels)}")
    report.append(f"Files skipped      : {skipped}")
    report.append("")
    report.append(f"Accuracy           : {acc:.4f}  ({acc*100:.2f}%)")
    report.append(f"Precision          : {prec:.4f}")
    report.append(f"Recall             : {rec:.4f}")
    report.append(f"F1-Score           : {f1:.4f}")
    report.append(f"False Positive Rate: {fpr:.4f}")
    report.append(f"False Negative Rate: {fnr:.4f}")
    report.append(f"Avg scan time (s)  : {avg_time:.4f}")
    report.append("")
    report.append("Confusion Matrix Counts:")
    report.append(f"  True Positives  (TP): {tp}")
    report.append(f"  True Negatives  (TN): {tn}")
    report.append(f"  False Positives (FP): {fp}")
    report.append(f"  False Negatives (FN): {fn}")
    report.append("")
    report.append("Full classification report:")
    report.append(classification_report(
        true_labels, predictions,
        target_names=["benign", "malicious"], zero_division=0,
    ))
    report_text = "\n".join(report)

    with open("metrics.txt", "w") as f:
        f.write(report_text)

    print("\n" + report_text)
    print("Saved metrics.txt")

    # Save confusion matrix chart
    disp = ConfusionMatrixDisplay(
        confusion_matrix=cm, display_labels=["benign", "malicious"]
    )
    disp.plot(cmap="Blues", values_format="d")
    plt.title("PDFSafeScan Confusion Matrix (Evasive-PDFMal2022)")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png", dpi=150)
    print("Saved confusion_matrix.png")

    print("\n" + "=" * 60)
    print("EVALUATION COMPLETE")
    print("=" * 60)
    print("Outputs: results.csv, metrics.txt, confusion_matrix.png")
    print("Use these in your Results chapter.")


if __name__ == "__main__":
    main()
