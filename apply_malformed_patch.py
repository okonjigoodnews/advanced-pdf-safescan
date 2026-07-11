#!/usr/bin/env python3
"""
========================================================================
APPLY THE MALFORMED-PDF TUNING PATCH
========================================================================
Edits app/main.py to raise the malformed-PDF signal from medium to
critical severity, and to separate encrypted files (a legitimate PDF
feature) from malformed ones (a strong malicious indicator).

EVIDENCE BEHIND THE CHANGE (measured on 31,006 files):
    benign parse-failure rate     : 0.05%
    malicious parse-failure rate  : 66.99%
    of all parse failures, 99.97% were malicious

WHAT IT DOES:
    1. Backs up app/main.py to app/main.py.backup
    2. Adds the PDFEncryptedError import
    3. Replaces _build_fallback_rule_result
    4. Replaces _build_fallback_final_decision
    5. Updates the call site to pass parser_error through
    6. Compiles the result to prove nothing is broken

It checks every anchor BEFORE changing anything. If it cannot find
something it expects, it aborts and changes nothing.

RUN (from project root, .venv active):
    python apply_malformed_patch.py

To undo:
    mv app/main.py.backup app/main.py
========================================================================
"""

import py_compile
import re
import shutil
import sys
from pathlib import Path

TARGET = Path("app/main.py")
BACKUP = Path("app/main.py.backup")


NEW_RULE_FN = '''def _build_fallback_rule_result(
    rule_result: dict[str, Any],
    parser_error: PDFParserError,
) -> dict[str, Any]:
    """Escalate the rule result when a PDF could not be parsed.

    Empirical basis: across a corpus of 31,006 PDFs, only 0.05 percent of
    benign files failed to parse, compared with 66.99 percent of malicious
    files. Of every file that failed to parse, 99.97 percent were malicious.
    Malformed structure is therefore treated as a critical indicator.

    Encryption is handled separately, because it is a legitimate feature of
    the PDF format and most benign parse failures in the corpus were
    encrypted rather than malformed.
    """
    fallback_result = dict(rule_result)
    triggered_rules = list(fallback_result.get("triggered_rules", []))
    explanations = list(fallback_result.get("explanations", []))

    if isinstance(parser_error, PDFEncryptedError):
        if "encrypted-pdf" not in triggered_rules:
            triggered_rules.append("encrypted-pdf")
        explanations.append(
            "[medium] encrypted-pdf: The PDF is encrypted and could not be "
            "fully inspected, so its contents could not be verified."
        )
        raw_score = max(int(fallback_result.get("risk_score_raw", 0)), 15)
        normalized_score = max(
            int(fallback_result.get("risk_score_normalized", 0)), 25
        )
        severity = "medium"
    else:
        if "malformed-pdf-structure" not in triggered_rules:
            triggered_rules.append("malformed-pdf-structure")
        explanations.append(
            "[critical] malformed-pdf-structure: The PDF could not be parsed "
            f"({parser_error}). Deliberately corrupted structure is a common "
            "evasion technique and is strongly associated with malicious "
            "documents."
        )
        raw_score = max(int(fallback_result.get("risk_score_raw", 0)), 80)
        normalized_score = max(
            int(fallback_result.get("risk_score_normalized", 0)), 85
        )
        severity = "critical"

    fallback_result["risk_score_raw"] = raw_score
    fallback_result["risk_score_normalized"] = normalized_score
    fallback_result["severity"] = severity
    fallback_result["triggered_rules"] = triggered_rules
    fallback_result["explanations"] = explanations
    return fallback_result
'''


NEW_DECISION_FN = '''def _build_fallback_final_decision(
    rule_result: dict[str, Any],
    ml_result: Any,
    parser_error: PDFParserError | None = None,
) -> dict[str, Any]:
    """Build the verdict for a PDF that could not be parsed.

    A malformed file is reported with high confidence, because parse failure
    was 99.97 percent precise for malice in the evaluation corpus. The label
    remains suspicious rather than malicious, because 99.97 percent is not
    certainty and a small number of legitimate PDFs are genuinely malformed.
    """
    ml_confidence = _safe_float(getattr(ml_result, "confidence", 0.0))
    is_encrypted = isinstance(parser_error, PDFEncryptedError)

    if is_encrypted:
        final_confidence = round(max(0.50, min(0.65, ml_confidence)), 3)
    else:
        final_confidence = 0.90

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
'''


def extract_function(source, func_name):
    """Return the full text of a top-level function, or None."""
    pattern = re.compile(
        rf"^def {re.escape(func_name)}\(.*?(?=^def |^class |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(source)
    return match.group(0) if match else None


def main():
    if not TARGET.exists():
        print(f"ERROR: {TARGET} not found. Run this from the project root.")
        return 1

    source = TARGET.read_text()
    print("=" * 66)
    print("MALFORMED-PDF TUNING PATCH")
    print("=" * 66)

    # ---- check every anchor BEFORE touching anything ----
    problems = []

    import_old = ("from src.parser.document_parser import "
                  "PDFMalformedError, PDFParser, PDFParserError")
    has_import = import_old in source
    already_imported = "PDFEncryptedError" in source
    if not has_import and not already_imported:
        problems.append("Could not find the document_parser import line.")

    old_rule_fn = extract_function(source, "_build_fallback_rule_result")
    if old_rule_fn is None:
        problems.append("Could not find _build_fallback_rule_result.")

    old_decision_fn = extract_function(source, "_build_fallback_final_decision")
    if old_decision_fn is None:
        problems.append("Could not find _build_fallback_final_decision.")

    call_old = ("final_decision = _build_fallback_final_decision("
                "rule_result, ml_result)")
    call_alt = "_build_fallback_final_decision(rule_result, ml_result)"
    has_call = call_alt in source
    already_patched_call = "ml_result, parser_error" in source
    if not has_call and not already_patched_call:
        problems.append("Could not find the _build_fallback_final_decision call.")

    if problems:
        print("\nABORTED. Nothing was changed. Problems found:")
        for p in problems:
            print(f"  - {p}")
        print("\nYour app/main.py may differ from what was expected.")
        print("Apply the changes by hand using malformed_tuning_patch.md")
        return 1

    # ---- back up ----
    shutil.copy2(TARGET, BACKUP)
    print(f"\nBacked up {TARGET} -> {BACKUP}")

    patched = source
    changes = []

    # 1. import
    if has_import:
        import_new = (
            "from src.parser.document_parser import (\n"
            "    PDFEncryptedError,\n"
            "    PDFMalformedError,\n"
            "    PDFParser,\n"
            "    PDFParserError,\n"
            ")"
        )
        patched = patched.replace(import_old, import_new, 1)
        changes.append("Added PDFEncryptedError to the imports")
    else:
        changes.append("Import already includes PDFEncryptedError (skipped)")

    # 2. rule result function
    patched = patched.replace(old_rule_fn, NEW_RULE_FN + "\n\n", 1)
    changes.append("Replaced _build_fallback_rule_result "
                   "(medium/25 -> critical/85, encrypted split out)")

    # 3. final decision function
    old_decision_fn_current = extract_function(
        patched, "_build_fallback_final_decision")
    patched = patched.replace(old_decision_fn_current, NEW_DECISION_FN + "\n\n", 1)
    changes.append("Replaced _build_fallback_final_decision "
                   "(confidence 0.55-0.75 -> 0.90 for malformed)")

    # 4. call site
    if call_alt in patched:
        patched = patched.replace(
            call_alt,
            "_build_fallback_final_decision(\n"
            "            rule_result, ml_result, parser_error\n"
            "        )",
            1,
        )
        changes.append("Updated the call site to pass parser_error through")

    TARGET.write_text(patched)

    # ---- verify it compiles ----
    try:
        py_compile.compile(str(TARGET), doraise=True)
    except py_compile.PyCompileError as exc:
        print("\nERROR: the patched file does not compile. Rolling back.")
        shutil.copy2(BACKUP, TARGET)
        print(f"Restored from {BACKUP}. Nothing was changed.")
        print(f"\nDetail: {exc}")
        return 1

    print("\nChanges applied:")
    for c in changes:
        print(f"  - {c}")

    print("\nThe file compiles cleanly.")
    print("\nWHAT CHANGED IN BEHAVIOUR")
    print("-" * 66)
    print("  Malformed PDF : severity medium -> CRITICAL")
    print("                  rule score 25   -> 85")
    print("                  confidence      -> 0.90")
    print("                  rule name       -> malformed-pdf-structure")
    print("  Encrypted PDF : now handled separately at medium severity")
    print("  Verdict stays 'suspicious', not 'malicious' "
          "(99.97% is strong, not certain)")

    print("\nNEXT STEPS")
    print("-" * 66)
    print("  1. Check it imports:   python -c \"import app.main; print('ok')\"")
    print("  2. Run your tests:     python -m pytest tests/ -q")
    print("  3. If a test fails on the old 'unreadable-pdf' name, update it")
    print("     to expect 'malformed-pdf-structure' and severity 'critical'.")
    print("\n  To undo everything:   mv app/main.py.backup app/main.py")
    print("=" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())
