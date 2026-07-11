#!/usr/bin/env python3
"""
========================================================================
IMPROVED SYSTEM EVALUATION  —  before vs after
========================================================================
The parse coverage analysis showed that a PDF which fails to parse is
almost always malicious (99.97% of parse failures were malicious, and
only 0.05% of benign files failed).

The ORIGINAL pipeline treated a parse failure as an ERROR and silently
discarded the file. That means it never classified roughly 67% of the
malicious corpus at all.

The IMPROVED pipeline treats a parse failure as a DETECTION SIGNAL:

    "Suspicious: the file could not be parsed. Malformed structure
     is a strong indicator of malicious intent."

This script measures both systems on the SAME held-out test set, so the
improvement can be stated with evidence.

IMPORTANT: it evaluates on the FULL corpus, including the files the old
pipeline threw away. That is the honest, real-world comparison.

IT ALSO FIXES THE PROVENANCE PROBLEM.
It writes full_dataset.csv with a SHA-256 for every row, so from now on
every feature row can be traced back to the exact file it came from.

WHAT IT PRODUCES:
    full_dataset.csv       : features + sha256 + parse_ok + label
    improved_results.txt   : the before/after comparison
    improved_chart.png     : chart for the dissertation

HOW TO RUN (from project root, .venv active):
    python improved_system_eval.py

First run re-parses every PDF and takes several minutes. It caches the
result, so later runs are fast. Use --rebuild to force a re-parse.
========================================================================
"""

import argparse
import contextlib
import hashlib
import io
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)

PROJECT_ROOT = Path(__file__).resolve().parents[0]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.extractor import PDFFeatureExtractor
from src.parser.document_parser import PDFParser

BENIGN_DIR = PROJECT_ROOT / "data" / "expanded" / "benign"
MALICIOUS_DIR = PROJECT_ROOT / "data" / "expanded" / "malicious"
CACHE_CSV = PROJECT_ROOT / "full_dataset.csv"
PDF_MAGIC = b"%PDF"
RANDOM_STATE = 42
TEST_SIZE = 0.2

# The real rule engine, copied from src/rules/engine.py
THRESHOLDS = {
    "suspicious_keyword_total_high": 8,
    "high_risk_keyword_total_high": 4,
    "action_keyword_total_high": 3,
}
RULE_DEFINITIONS = [
    ("launch-action-present", lambda r: bool(r.get("has_launch", 0)), 35),
    ("openaction-with-javascript",
     lambda r: bool(r.get("has_openaction", 0)) and
               (bool(r.get("has_javascript", 0)) or bool(r.get("has_js", 0))), 45),
    ("embedded-file-present", lambda r: bool(r.get("has_embeddedfile", 0)), 22),
    ("high-suspicious-keyword-volume",
     lambda r: int(r.get("suspicious_keyword_total", 0)) >=
               THRESHOLDS["suspicious_keyword_total_high"], 15),
    ("high-high-risk-keyword-volume",
     lambda r: int(r.get("high_risk_keyword_total", 0)) >=
               THRESHOLDS["high_risk_keyword_total_high"], 18),
    ("encrypted-with-active-indicators",
     lambda r: bool(r.get("is_encrypted", 0)) and (
         bool(r.get("has_javascript", 0)) or bool(r.get("has_js", 0)) or
         bool(r.get("has_openaction", 0)) or bool(r.get("has_aa", 0)) or
         bool(r.get("has_launch", 0))), 20),
    ("multiple-action-indicators",
     lambda r: int(r.get("action_keyword_total", 0)) >=
               THRESHOLDS["action_keyword_total_high"], 15),
]
MAX_RULE_SCORE = sum(s for _, _, s in RULE_DEFINITIONS)


def rule_score(row):
    """Normalised 0..1 rule risk score."""
    raw = 0
    for _n, cond, score in RULE_DEFINITIONS:
        try:
            if cond(row):
                raw += score
        except Exception:
            pass
    return (raw / MAX_RULE_SCORE) if MAX_RULE_SCORE else 0.0


def sha256_of(path):
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_full_dataset():
    """Parse every PDF, recording features, sha256 and whether it parsed."""
    parser = PDFParser()
    extractor = PDFFeatureExtractor()
    feature_names = list(extractor.extract({}).keys())

    rows = []
    for folder, label in ((BENIGN_DIR, "benign"), (MALICIOUS_DIR, "malicious")):
        files = [p for p in sorted(folder.rglob("*")) if p.is_file()]
        print(f"\nProcessing {len(files)} {label} files...")
        start = time.time()
        for i, path in enumerate(files, 1):
            record = {"sha256": "", "label": label, "parse_ok": 0}
            try:
                record["sha256"] = sha256_of(path)
            except OSError:
                pass

            parsed_ok = False
            feats = {}
            try:
                with path.open("rb") as fh:
                    if PDF_MAGIC not in fh.read(1024):
                        raise ValueError("no PDF header")
                with contextlib.redirect_stderr(io.StringIO()):
                    parsed = parser.parse(path)
                    feats = extractor.extract(parsed)
                parsed_ok = True
            except Exception:
                parsed_ok = False

            record["parse_ok"] = 1 if parsed_ok else 0
            for name in feature_names:
                value = feats.get(name, 0) if parsed_ok else 0
                if isinstance(value, bool):
                    value = int(value)
                record[name] = value
            rows.append(record)

            if i % 2000 == 0:
                rate = i / (time.time() - start)
                print(f"  {label}: {i}/{len(files)}  ({rate:.0f}/sec)")

    df = pd.DataFrame(rows)
    df.to_csv(CACHE_CSV, index=False)
    print(f"\nSaved {CACHE_CSV} with {len(df)} rows (features + sha256 + parse_ok).")
    return df


def metrics(y_true, y_pred, name):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "name": name,
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rebuild", action="store_true",
                    help="Force a full re-parse instead of using the cache.")
    args = ap.parse_args()

    print("=" * 70)
    print("IMPROVED SYSTEM EVALUATION: before vs after")
    print("=" * 70)

    if CACHE_CSV.exists() and not args.rebuild:
        print(f"\nUsing cached {CACHE_CSV.name} (pass --rebuild to re-parse).")
        df = pd.read_csv(CACHE_CSV)
    else:
        df = build_full_dataset()

    meta_cols = ["sha256", "label", "parse_ok"]
    feature_cols = [c for c in df.columns if c not in meta_cols]

    y = (df["label"].astype(str).str.lower() == "malicious").astype(int).values
    parse_ok = df["parse_ok"].astype(int).values
    X = df[feature_cols].replace({True: 1, False: 0}) \
                        .apply(pd.to_numeric, errors="coerce").fillna(0)

    n_total = len(df)
    n_mal = int(y.sum())
    n_ben = n_total - n_mal
    n_unparseable = int((parse_ok == 0).sum())
    n_unparse_mal = int(((parse_ok == 0) & (y == 1)).sum())
    n_unparse_ben = int(((parse_ok == 0) & (y == 0)).sum())

    print(f"\nCorpus: {n_total} files ({n_mal} malicious, {n_ben} benign)")
    print(f"Unparseable: {n_unparseable} "
          f"({n_unparse_mal} malicious, {n_unparse_ben} benign)")

    # ---- split the FULL corpus, stratified ----
    idx = np.arange(n_total)
    idx_tr, idx_te = train_test_split(
        idx, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y)

    # ---- the model is trained ONLY on files that parse ----
    tr_parse = idx_tr[parse_ok[idx_tr] == 1]
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X.iloc[tr_parse])
    y_tr = y[tr_parse]
    model = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)
    model.fit(X_tr, y_tr)
    print(f"\nModel trained on {len(tr_parse)} parseable training files.")

    # ---- predict on the test set ----
    y_te = y[idx_te]
    parse_te = parse_ok[idx_te]
    X_te_all = X.iloc[idx_te]

    probs = np.zeros(len(idx_te))
    mask_ok = parse_te == 1
    if mask_ok.sum():
        probs[mask_ok] = model.predict_proba(
            scaler.transform(X_te_all[mask_ok]))[:, 1]

    rule_probs = np.zeros(len(idx_te))
    raw_te = X_te_all.to_dict("records")
    for i, r in enumerate(raw_te):
        rule_probs[i] = rule_score(r) if parse_te[i] == 1 else 0.0

    # weighted fusion (model 0.70), the best strategy from the fusion study
    fused = 0.70 * probs + 0.30 * rule_probs

    n_te = len(idx_te)
    n_te_unparse = int((parse_te == 0).sum())
    print(f"Test set: {n_te} files, of which {n_te_unparse} do not parse.")

    # ================= SYSTEM A: ORIGINAL =================
    # Unparseable files are dropped as errors. In the real world a file
    # with no verdict passes through to the user, so it counts as benign.
    pred_before = np.zeros(n_te, dtype=int)
    pred_before[mask_ok] = (fused[mask_ok] >= 0.5).astype(int)
    # unparseable stay 0 (benign / passed through)
    m_before = metrics(y_te, pred_before, "BEFORE: parse failure = dropped")

    # ================= SYSTEM B: IMPROVED =================
    # Unparseable files are flagged as suspicious (treated as malicious).
    pred_after = pred_before.copy()
    pred_after[parse_te == 0] = 1
    m_after = metrics(y_te, pred_after, "AFTER: parse failure = suspicious")

    # ---- coverage ----
    mal_te = int(y_te.sum())
    mal_classified_before = int(((y_te == 1) & (parse_te == 1)).sum())
    coverage_before = mal_classified_before / mal_te * 100 if mal_te else 0
    coverage_after = 100.0

    # ---- report ----
    L = []
    L.append("IMPROVED SYSTEM EVALUATION: treating parse failure as a signal")
    L.append("=" * 70)
    L.append("")
    L.append("CORPUS")
    L.append(f"  Total files        : {n_total}")
    L.append(f"  Malicious          : {n_mal}")
    L.append(f"  Benign             : {n_ben}")
    L.append(f"  Unparseable        : {n_unparseable} "
             f"({n_unparse_mal} malicious, {n_unparse_ben} benign)")
    L.append("")
    L.append(f"HELD-OUT TEST SET: {n_te} files "
             f"({mal_te} malicious, {n_te - mal_te} benign)")
    L.append(f"  of which unparseable: {n_te_unparse}")
    L.append("")
    L.append("RESULTS ON THE SAME TEST SET")
    L.append("-" * 70)
    L.append(f"{'System':<38}{'Acc':>8}{'Prec':>8}{'Rec':>8}{'F1':>8}{'FPR':>7}")
    for m in (m_before, m_after):
        L.append(f"{m['name']:<38}"
                 f"{m['accuracy']*100:>7.2f}%"
                 f"{m['precision']*100:>7.2f}%"
                 f"{m['recall']*100:>7.2f}%"
                 f"{m['f1']*100:>7.2f}%"
                 f"{m['fpr']*100:>6.2f}%")
    L.append("")
    L.append("ERRORS (FN = malicious that got through, FP = false alarms)")
    for m in (m_before, m_after):
        L.append(f"  {m['name']:<38} FN={m['fn']:<6} FP={m['fp']}")
    L.append("")
    L.append("MALICIOUS COVERAGE (files the system actually gives a verdict on)")
    L.append("-" * 70)
    L.append(f"  BEFORE : {mal_classified_before}/{mal_te} = {coverage_before:.1f}%")
    L.append(f"  AFTER  : {mal_te}/{mal_te} = {coverage_after:.1f}%")
    L.append("")
    L.append("IMPROVEMENT")
    L.append("-" * 70)
    L.append(f"  Recall  : {m_before['recall']*100:.2f}%  ->  "
             f"{m_after['recall']*100:.2f}%   "
             f"({(m_after['recall']-m_before['recall'])*100:+.2f} points)")
    L.append(f"  F1      : {m_before['f1']*100:.2f}%  ->  "
             f"{m_after['f1']*100:.2f}%   "
             f"({(m_after['f1']-m_before['f1'])*100:+.2f} points)")
    L.append(f"  Accuracy: {m_before['accuracy']*100:.2f}%  ->  "
             f"{m_after['accuracy']*100:.2f}%   "
             f"({(m_after['accuracy']-m_before['accuracy'])*100:+.2f} points)")
    L.append(f"  Malicious files that got through: "
             f"{m_before['fn']}  ->  {m_after['fn']}")
    L.append(f"  Cost: false alarms rose from {m_before['fp']} to {m_after['fp']} "
             f"(the {n_unparse_ben} unparseable benign files, mostly encrypted).")
    L.append("")
    L.append("PROVENANCE FIXED")
    L.append("-" * 70)
    L.append(f"  full_dataset.csv now records a SHA-256 for every row, so each")
    L.append(f"  feature row can be traced back to the exact source file.")

    report = "\n".join(L)
    with open("improved_results.txt", "w") as f:
        f.write(report)
    print("\n" + report)
    print("\nSaved improved_results.txt")

    # ---- chart ----
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), dpi=150)

        names = ["Accuracy", "Precision", "Recall", "F1"]
        before = [m_before["accuracy"]*100, m_before["precision"]*100,
                  m_before["recall"]*100, m_before["f1"]*100]
        after = [m_after["accuracy"]*100, m_after["precision"]*100,
                 m_after["recall"]*100, m_after["f1"]*100]
        x = np.arange(len(names)); w = 0.36
        b1 = ax1.bar(x - w/2, before, w, label="Before (failures dropped)",
                     color="#B0B7C3")
        b2 = ax1.bar(x + w/2, after, w, label="After (failures flagged)",
                     color="#22C55E")
        for bars in (b1, b2):
            for b in bars:
                ax1.text(b.get_x()+b.get_width()/2, b.get_height()+1,
                         f"{b.get_height():.1f}", ha="center", fontsize=8)
        ax1.set_xticks(x); ax1.set_xticklabels(names)
        ax1.set_ylabel("Percentage"); ax1.set_ylim(0, 112)
        ax1.set_title("Detection Performance: Before vs After",
                      fontsize=12, fontweight="bold", color="#1F3A5F")
        ax1.legend(fontsize=9, loc="lower right")
        for s in ["top","right"]: ax1.spines[s].set_visible(False)

        cov = [coverage_before, coverage_after]
        bars = ax2.bar(["Before", "After"], cov, 0.5,
                       color=["#D12D3F", "#22C55E"])
        for b, v in zip(bars, cov):
            ax2.text(b.get_x()+b.get_width()/2, v+2, f"{v:.1f}%",
                     ha="center", fontsize=13, fontweight="bold")
        ax2.set_ylabel("Malicious files given a verdict (%)")
        ax2.set_ylim(0, 115)
        ax2.set_title("Malicious Coverage: the Real Gain",
                      fontsize=12, fontweight="bold", color="#1F3A5F")
        for s in ["top","right"]: ax2.spines[s].set_visible(False)

        plt.tight_layout()
        plt.savefig("improved_chart.png", dpi=150, facecolor="white")
        print("Saved improved_chart.png")
    except Exception as e:
        print(f"(Chart skipped: {e})")

    print("\n" + "=" * 70)
    print("DONE. Paste improved_results.txt back.")
    print("=" * 70)


if __name__ == "__main__":
    main()
