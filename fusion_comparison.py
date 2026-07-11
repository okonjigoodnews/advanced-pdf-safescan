#!/usr/bin/env python3
"""
========================================================================
FUSION STRATEGY COMPARISON
========================================================================
The first ablation showed that averaging the model probability with the
rule score makes the hybrid WORSE than the model alone, because a weak
rule score drags down a confident model prediction (the rules end up
vetoing the model).

This script tests smarter ways of combining the two signals, to find
out whether a hybrid can beat the model alone when the fusion is done
properly. All strategies are evaluated on the SAME held-out test set.

STRATEGIES TESTED:
  1. ML only                  (baseline to beat)
  2. Average                  (the original, for comparison)
  3. OR-escalation            (malicious if EITHER model OR strong rules)
  4. Weighted average         (model weighted more heavily than rules)
  5. Rules-as-override        (model decides, rules can only escalate)

All thresholds are chosen on the TRAINING data only, never on the test
data, so the comparison is fair.

RUN (from project root, .venv active):
    python fusion_comparison.py
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


def rule_score_for_row(row):
    raw = 0
    for _n, cond, score in RULE_DEFINITIONS:
        try:
            if cond(row):
                raw += score
        except Exception:
            pass
    return (raw / MAX_RULE_SCORE) if MAX_RULE_SCORE else 0.0  # 0..1


def metrics_for(y_true, y_pred, name):
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
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
    print("=" * 70)
    print("FUSION STRATEGY COMPARISON")
    print("=" * 70)

    df = pd.read_csv(CSV_PATH)
    y = (df[LABEL_COLUMN].astype(str).str.strip().str.lower() == "malicious").astype(int)
    X_raw = df.drop(columns=[LABEL_COLUMN])
    X = X_raw.replace({True: 1, False: 0}).apply(pd.to_numeric, errors="coerce").fillna(0)

    idx = np.arange(len(df))
    idx_tr, idx_te = train_test_split(idx, test_size=TEST_SIZE,
                                      random_state=RANDOM_STATE, stratify=y)
    X_tr, X_te = X.iloc[idx_tr], X.iloc[idx_te]
    y_tr, y_te = y.iloc[idx_tr], y.iloc[idx_te]
    raw_tr, raw_te = X_raw.iloc[idx_tr], X_raw.iloc[idx_te]
    print(f"\nTrain {len(X_tr)}, test {len(X_te)} held-out files.\n")

    # rule scores (0..1)
    r_tr = raw_tr.apply(rule_score_for_row, axis=1).values
    r_te = raw_te.apply(rule_score_for_row, axis=1).values

    # model
    scaler = StandardScaler()
    Xtr_s = scaler.fit_transform(X_tr)
    Xte_s = scaler.transform(X_te)
    model = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)
    model.fit(Xtr_s, y_tr)
    p_tr = model.predict_proba(Xtr_s)[:, 1]
    p_te = model.predict_proba(Xte_s)[:, 1]

    results = []

    # 1. ML only (baseline)
    results.append(metrics_for(y_te, (p_te >= 0.5).astype(int), "1. ML only (baseline)"))

    # 2. Average (the original hybrid)
    results.append(metrics_for(y_te, (((p_te + r_te) / 2) >= 0.5).astype(int),
                               "2. Average (original)"))

    # 3. OR-escalation: malicious if model says so OR rules fire strongly.
    #    Rule trigger threshold chosen on TRAINING data.
    best_rt, best_f1 = 0.5, -1
    for rt in np.arange(0.05, 1.01, 0.05):
        pred_tr = ((p_tr >= 0.5) | (r_tr >= rt)).astype(int)
        s = f1_score(y_tr, pred_tr, zero_division=0)
        if s > best_f1:
            best_f1, best_rt = s, rt
    pred = ((p_te >= 0.5) | (r_te >= best_rt)).astype(int)
    results.append(metrics_for(y_te, pred, f"3. OR-escalate (rules>={best_rt:.2f})"))

    # 4. Weighted average: model weighted more heavily. Weight from TRAINING.
    best_w, best_f1 = 0.5, -1
    for w in np.arange(0.5, 1.01, 0.05):   # w = weight on model
        comb_tr = w * p_tr + (1 - w) * r_tr
        s = f1_score(y_tr, (comb_tr >= 0.5).astype(int), zero_division=0)
        if s > best_f1:
            best_f1, best_w = s, w
    comb_te = best_w * p_te + (1 - best_w) * r_te
    results.append(metrics_for(y_te, (comb_te >= 0.5).astype(int),
                               f"4. Weighted avg (model {best_w:.2f})"))

    # 5. Rules-as-override: model decides; rules can only ESCALATE a
    #    borderline benign call, never suppress a malicious one.
    best_lo, best_rt5, best_f1 = 0.3, 0.5, -1
    for lo in np.arange(0.15, 0.50, 0.05):        # borderline band lower edge
        for rt in np.arange(0.10, 1.01, 0.10):    # rule strength to escalate
            pred_tr = (p_tr >= 0.5).astype(int)
            escalate = (p_tr >= lo) & (p_tr < 0.5) & (r_tr >= rt)
            pred_tr = np.where(escalate, 1, pred_tr)
            s = f1_score(y_tr, pred_tr, zero_division=0)
            if s > best_f1:
                best_f1, best_lo, best_rt5 = s, lo, rt
    pred = (p_te >= 0.5).astype(int)
    escalate = (p_te >= best_lo) & (p_te < 0.5) & (r_te >= best_rt5)
    pred = np.where(escalate, 1, pred)
    results.append(metrics_for(
        y_te, pred, f"5. Rules escalate only (p>={best_lo:.2f}, r>={best_rt5:.2f})"))

    # ---------------- REPORT ----------------
    lines = []
    lines.append("FUSION STRATEGY COMPARISON")
    lines.append("=" * 70)
    lines.append(f"Test set: {len(X_te)} held-out files "
                 f"({int(y_te.sum())} malicious, {int((y_te==0).sum())} benign)")
    lines.append("All thresholds tuned on TRAINING data only.")
    lines.append("")
    lines.append(f"{'Strategy':<38}{'Acc':>8}{'Prec':>8}{'Rec':>8}{'F1':>8}{'FPR':>7}")
    lines.append("-" * 70)
    for m in results:
        lines.append(f"{m['name']:<38}"
                     f"{m['accuracy']*100:>7.2f}%"
                     f"{m['precision']*100:>7.2f}%"
                     f"{m['recall']*100:>7.2f}%"
                     f"{m['f1']*100:>7.2f}%"
                     f"{m['fpr']*100:>6.2f}%")
    lines.append("")
    lines.append("Errors (FN = malicious missed, FP = false alarms):")
    for m in results:
        lines.append(f"  {m['name']:<38} FN={m['fn']:<5} FP={m['fp']}")
    lines.append("")

    baseline = results[0]
    best = max(results, key=lambda m: m["f1"])
    lines.append(f"BASELINE (ML only) F1 : {baseline['f1']*100:.2f}%")
    lines.append(f"BEST STRATEGY         : {best['name']} (F1 {best['f1']*100:.2f}%)")
    delta = (best["f1"] - baseline["f1"]) * 100
    if best["name"].startswith("1."):
        lines.append("")
        lines.append("HONEST FINDING: no fusion strategy beat the model alone on F1.")
        lines.append("The rule engine's value lies in explainability and in reducing")
        lines.append("false alarms, rather than in improving raw detection.")
    else:
        lines.append(f"IMPROVEMENT OVER ML   : {delta:+.2f} F1 points")

    report = "\n".join(lines)
    with open("fusion_comparison.txt", "w") as f:
        f.write(report)
    print(report)
    print("\nSaved fusion_comparison.txt")

    # chart
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(11, 5.5), dpi=150)
        names = [m["name"] for m in results]
        f1s = [m["f1"] * 100 for m in results]
        recs = [m["recall"] * 100 for m in results]
        precs = [m["precision"] * 100 for m in results]
        x = np.arange(len(names)); w = 0.26
        ax.bar(x - w, precs, w, label="Precision", color="#2D6CB5")
        ax.bar(x, recs, w, label="Recall", color="#E0A800")
        ax.bar(x + w, f1s, w, label="F1", color="#22C55E")
        for i, v in enumerate(f1s):
            ax.text(i + w, v + 0.8, f"{v:.1f}", ha="center", fontsize=8, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels([n.split(" (")[0] for n in names], fontsize=8, rotation=12)
        ax.set_ylabel("Percentage"); ax.set_ylim(0, 108)
        ax.set_title("Comparing Ways of Combining the Rules and the Model",
                     fontsize=13, fontweight="bold", color="#1F3A5F")
        ax.legend(fontsize=9); ax.grid(True, axis="y", alpha=0.2)
        for s in ["top", "right"]: ax.spines[s].set_visible(False)
        plt.tight_layout()
        plt.savefig("fusion_chart.png", dpi=150, facecolor="white")
        print("Saved fusion_chart.png")
    except Exception as e:
        print(f"(Chart skipped: {e})")

    print("\n" + "=" * 70)
    print("DONE. Paste fusion_comparison.txt back.")
    print("=" * 70)


if __name__ == "__main__":
    main()
