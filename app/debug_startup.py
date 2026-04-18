"""Debug startup script - run this to see exactly what is failing."""
import sys
import traceback

modules_to_test = [
    "streamlit",
    "app.main",
    "app.runtime_config",
    "src.ml.classifier",
    "src.parser.document_parser",
    "src.reporting.comparison",
    "src.reporting.csv_export",
    "src.reporting.explanations",
    "src.reporting.forensics",
    "src.reporting.history",
    "src.reporting.pdf_export",
    "src.reporting.pdf_reader",
    "src.reporting.review_notes",
    "src.reporting.summary",
    "src.reporting.zip_ingest",
]

print("=== DEBUG STARTUP TEST ===", flush=True)
all_ok = True
for module in modules_to_test:
    try:
        __import__(module)
        print(f"OK: {module}", flush=True)
    except Exception:
        print(f"FAILED: {module}", flush=True)
        traceback.print_exc()
        all_ok = False

if all_ok:
    print("=== ALL IMPORTS OK - problem is elsewhere ===", flush=True)
else:
    print("=== IMPORT FAILURES FOUND ABOVE ===", flush=True)
    sys.exit(1)
