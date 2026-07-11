#!/usr/bin/env python3
"""
========================================================================
ABLATION STUDY: Rules only vs Machine Learning only vs Hybrid
========================================================================
This answers the central research claim of the project: does combining
rule based analysis with machine learning actually beat either method
used on its own?

It evaluates three approaches on the SAME held-out test set:

    1. RULE ENGINE ONLY   (your 7 real rules from src/rules/engine.py)
    2. MACHINE LEARNING ONLY (Logistic Regression on the 32 features)
    3. HYBRID             (both combined)

The rule engine is given its best chance: the decision threshold is
chosen from the TRAINING data only, never from the test data.

WHAT IT PRODUCES:
    ablation_results.txt   : the full comparison, ready to paste
    ablation_chart.png     : a bar chart comparing the three
    feature_importance.txt : the model's top learned weights
    feature_importance.png : chart of the most important features

HOW TO RUN (from the project root, with .venv active):
    python ablation_study.py
========================================================================
"""

import warnings
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)

warnings.filterwarnings("ignore")

CSV_PATH = "data/features/train.csv"
TEST_SIZE = 0.2
RANDOM_STATE = 42
LABEL_COLUMN = "label"


# ----------------------------------------------------------------------
# YOUR REAL RULE ENGINE, replicated exactly from src/rules/engine.py
# ----------------------------------------------------------------------
THRESHOLDS = {
    "suspicious_keyword_total_high": 8,
    "high_risk_keyword_total_high": 4,
    "action_keyword_total_high": 3,
}

# (name, condition function, score)
RULE_DEFINITIONS = [
    ("launch-action-present",
     lambda r: bool(r.get("has_launch", 0)), 35),

    ("openaction-with-javascript",
     lambda r: bool(r.get("has_openaction", 0)) and
               (bool(r.get("has_javascript", 0)) or bool(r.get("has_js", 0))), 45),

    ("embedded-file-present",
     lambda r: bool(r.get("has_embeddedfile", 0)), 22),

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

MAX_RULE_SCORE = sum(score for _, _, score in RULE_DEFINITIONS)


def rule_score_for_row(row):
    """Return the normalised 0-100 rule risk score for one file."""
    raw = 0
    for _name, condition, score in RULE_DEFINITIONS:
        try:
            if condition(row):
                raw += score
        except Exception:
            pass
    return round((raw / MAX_RULE_SCORE) * 100) if MAX_RULE_SCORE else 0


def metrics_for(y_true, y_pred, name):
    """Compute the standard metric set for one approach."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    return {
        "name": name,
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "fnr": fn / (fn + tp) if (fn + tp) else 0.0,
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
    }


def main():
    print("=" * 66)
    print("ABLATION STUDY: Rules only  vs  ML only  vs  Hybrid")
    print("=" * 66)

    df = pd.read_csv(CSV_PATH)
    print(f"\nLoaded {len(df)} labelled files from {CSV_PATH}")

    y_raw = df[LABEL_COLUMN].astype(str).str.strip().str.lower()
    y = (y_raw == "malicious").astype(int)
    X_raw = df.drop(columns=[LABEL_COLUMN])
    X = X_raw.replace({True: 1, False: 0}).apply(pd.to_numeric, errors="coerce").fillna(0)

    # Same split as the main evaluation, so results are comparable
    idx = np.arange(len(df))
    idx_train, idx_test = train_test_split(
        idx, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    X_train, X_test = X.iloc[idx_train], X.iloc[idx_test]
    y_train, y_test = y.iloc[idx_train], y.iloc[idx_test]
    raw_train, raw_test = X_raw.iloc[idx_train], X_raw.iloc[idx_test]

    print(f"Training on {len(X_train)} files, testing on {len(X_test)} held-out files.\n")

    # ---------------- 1. RULE ENGINE ONLY ----------------
    # Compute the rule score for every file
    rule_scores_train = raw_train.apply(rule_score_for_row, axis=1).values
    rule_scores_test = raw_test.apply(rule_score_for_row, axis=1).values

    # Choose the threshold using ONLY the training data (fair to the rules)
    best_threshold, best_f1 = 50, -1.0
    for threshold in range(0, 101, 1):
        pred = (rule_scores_train >= threshold).astype(int)
        score = f1_score(y_train, pred, zero_division=0)
        if score > best_f1:
            best_f1, best_threshold = score, threshold
    print(f"Rule engine: best threshold learned from training data = {best_threshold}")

    rules_pred = (rule_scores_test >= best_threshold).astype(int)
    m_rules = metrics_for(y_test, rules_pred, "Rule engine only")

    # ---------------- 2. MACHINE LEARNING ONLY ----------------
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    model = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)
    model.fit(X_train_s, y_train)

    ml_prob = model.predict_proba(X_test_s)[:, 1]
    ml_pred = (ml_prob >= 0.5).astype(int)
    m_ml = metrics_for(y_test, ml_pred, "Machine learning only")

    # ---------------- 3. HYBRID ----------------
    # Combine: the model probability and the normalised rule score (0-1),
    # averaged. This mirrors the system's fusion of the two signals.
    rule_prob_test = rule_scores_test / 100.0
    hybrid_score = (ml_prob + rule_prob_test) / 2.0
    hybrid_pred = (hybrid_score >= 0.5).astype(int)
    m_hybrid = metrics_for(y_test, hybrid_pred, "Hybrid (rules + ML)")

    # ---------------- REPORT ----------------
    results = [m_rules, m_ml, m_hybrid]
    lines = []
    lines.append("ABLATION STUDY RESULTS")
    lines.append("=" * 66)
    lines.append(f"Test set: {len(X_test)} held-out files "
                 f"({int(y_test.sum())} malicious, {int((y_test==0).sum())} benign)")
    lines.append(f"Rule engine threshold (learned from training data): {best_threshold}")
    lines.append("")
    header = f"{'Approach':<24}{'Acc':>8}{'Prec':>9}{'Recall':>9}{'F1':>9}{'FPR':>8}"
    lines.append(header)
    lines.append("-" * 66)
    for m in results:
        lines.append(
            f"{m['name']:<24}"
            f"{m['accuracy']*100:>7.2f}%"
            f"{m['precision']*100:>8.2f}%"
            f"{m['recall']*100:>8.2f}%"
            f"{m['f1']*100:>8.2f}%"
            f"{m['fpr']*100:>7.2f}%"
        )
    lines.append("")
    lines.append("Confusion matrix detail (TP = malicious caught, FN = malicious missed):")
    for m in results:
        lines.append(f"  {m['name']:<24} TP={m['tp']:<5} TN={m['tn']:<6} "
                     f"FP={m['fp']:<5} FN={m['fn']}")
    lines.append("")

    # Honest verdict
    best = max(results, key=lambda m: m["f1"])
    lines.append(f"Best F1 score: {best['name']} ({best['f1']*100:.2f}%)")
    gain_over_ml = (m_hybrid["f1"] - m_ml["f1"]) * 100
    gain_over_rules = (m_hybrid["f1"] - m_rules["f1"]) * 100
    lines.append(f"Hybrid vs ML only:    {gain_over_ml:+.2f} F1 points")
    lines.append(f"Hybrid vs rules only: {gain_over_rules:+.2f} F1 points")

    report = "\n".join(lines)
    with open("ablation_results.txt", "w") as f:
        f.write(report)
    print("\n" + report)
    print("\nSaved ablation_results.txt")

    # ---------------- FEATURE IMPORTANCE ----------------
    coefs = model.coef_[0]
    names = list(X.columns)
    pairs = sorted(zip(names, coefs), key=lambda kv: abs(kv[1]), reverse=True)

    fi_lines = ["MODEL FEATURE IMPORTANCE (learned weights)",
                "=" * 60,
                "Positive weight pushes toward MALICIOUS.",
                "Negative weight pushes toward BENIGN.",
                "These weights were LEARNED from the training data.",
                ""]
    for name, w in pairs[:15]:
        direction = "-> malicious" if w > 0 else "-> benign"
        fi_lines.append(f"  {name:<32} {w:+.4f}   {direction}")
    fi_report = "\n".join(fi_lines)
    with open("feature_importance.txt", "w") as f:
        f.write(fi_report)
    print("\n" + fi_report)
    print("\nSaved feature_importance.txt")

    # ---------------- CHARTS ----------------
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        # Ablation comparison chart
        fig, ax = plt.subplots(figsize=(9, 5), dpi=150)
        metrics_names = ["Accuracy", "Precision", "Recall", "F1"]
        x = np.arange(len(metrics_names))
        width = 0.26
        colors = ["#E0A800", "#2D6CB5", "#22C55E"]
        for i, m in enumerate(results):
            vals = [m["accuracy"]*100, m["precision"]*100, m["recall"]*100, m["f1"]*100]
            bars = ax.bar(x + (i-1)*width, vals, width, label=m["name"], color=colors[i])
            for b, v in zip(bars, vals):
                ax.text(b.get_x()+b.get_width()/2, v+0.6, f"{v:.1f}",
                        ha="center", fontsize=8)
        ax.set_xticks(x); ax.set_xticklabels(metrics_names)
        ax.set_ylabel("Percentage")
        ax.set_ylim(0, 108)
        ax.set_title("Rules only vs Machine Learning only vs Hybrid",
                     fontsize=13, fontweight="bold", color="#1F3A5F")
        ax.legend(loc="lower right", fontsize=9)
        ax.grid(True, axis="y", alpha=0.2)
        for s in ["top","right"]: ax.spines[s].set_visible(False)
        plt.tight_layout()
        plt.savefig("ablation_chart.png", dpi=150, facecolor="white")
        print("Saved ablation_chart.png")

        # Feature importance chart (top 12)
        top = pairs[:12][::-1]
        fig2, ax2 = plt.subplots(figsize=(9, 6), dpi=150)
        fnames = [n for n, _ in top]
        fvals = [w for _, w in top]
        bcolors = ["#D12D3F" if w > 0 else "#2D6A4F" for w in fvals]
        ax2.barh(fnames, fvals, color=bcolors)
        ax2.axvline(0, color="#555", linewidth=0.8)
        ax2.set_xlabel("Learned weight  (positive = pushes toward malicious)")
        ax2.set_title("What the Model Learned: Most Influential Features",
                      fontsize=13, fontweight="bold", color="#1F3A5F")
        ax2.grid(True, axis="x", alpha=0.2)
        for s in ["top","right"]: ax2.spines[s].set_visible(False)
        plt.tight_layout()
        plt.savefig("feature_importance.png", dpi=150, facecolor="white")
        print("Saved feature_importance.png")
    except Exception as e:
        print(f"(Charts skipped: {e})")

    print("\n" + "=" * 66)
    print("DONE. Paste ablation_results.txt and feature_importance.txt back.")
    print("=" * 66)


if __name__ == "__main__":
    main()
