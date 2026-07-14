# Advanced PDFSafeScan

**A hybrid machine learning and rule-based system for explainable, real-time detection of malicious PDF files at the browser level.**

MSc Cyber Security dissertation project · De Montfort University · Goodnews Peter Okonji

| | |
|---|---|
| **Dashboard** | https://advanced-pdf-safescan-dashboard.onrender.com |
| **Backend API** | https://advanced-pdf-safescan-api.onrender.com |
| **Verdicts** | `benign` · `suspicious` · `malicious` |
| **Model** | Logistic Regression, 32 structural features |

---

## The finding this project is built on

Most published PDF malware detectors report an accuracy figure. Almost none report **how many of the malicious files their parser could actually read**.

That turned out to matter enormously. Measured across **31,006 files**:

| Measurement | Result |
|---|---|
| Malicious PDFs that fail to parse | **67%** |
| Benign PDFs that fail to parse | **0.05%** |
| Parse failures that are malicious | **99.97%** |

A PDF that cannot be parsed is not missing data. **It is the strongest single malicious signal in the corpus.**

### These files are weapons, not wreckage

The obvious objection is that a malformed file might simply be a broken file, which would make this an artifact of how the malware corpus was packaged rather than a property of malware. That objection was tested directly.

Every malicious file rejected by the strict parser was re-opened with a lenient real-world PDF engine (Poppler). **94% still open and render correctly**, and every one carries a valid `%PDF-` header. They are not corrupted carcasses. They are **deliberately malformed so that analysis tools choke while a real reader still opens the file** — a documented technique known as parser-differential evasion.

Treating malformed structure as a critical signal therefore closes a real evasion channel rather than papering over a data-quality problem.

### What it changed

| | Before | After |
|---|---|---|
| End-to-end accuracy | 50% | **97.58%** |
| Malware actually assessed | 33% | **100%** |

The earlier figure of **98.05% was correct** — but only for the parseable third of the malware. The system was silently discarding the files most likely to be dangerous and then reporting excellent accuracy on what remained.

---

## Honest results

### The hybrid does not improve raw accuracy

The research question asked whether combining rules with machine learning beats a single method. **It does not**, and this is reported rather than buried.

| Approach | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Rule engine only | 86.44% | 82.84% | 56.35% | 67.07% |
| **Machine learning only** | **98.05%** | **96.42%** | **95.60%** | **96.01%** |
| Hybrid (naive averaging) | 88.81% | 98.78% | 54.99% | 70.65% |

Naive averaging lets a weak rule score veto a confident model, and recall collapses. The model has already learned what the rules encode.

**The rules still earn their place** — not through accuracy, but through a near-zero false positive rate and the human-readable reasons attached to every verdict. Explainability is the point of the rule layer, not detection performance.

### Two defects found, diagnosed and fixed

1. **Rule normalisation** — no malicious file in 4,000 ever exceeded `medium` severity. The worst offender tripped five rules and still scored only 39 out of 100.
2. **Fusion gating** — the system was *structurally incapable* of ever returning a `malicious` verdict, no matter how confident the model was.

Both are fixed, covered by **138 passing tests**, and deployed.

### Known limitations

Stated plainly, because they affect how the headline number should be read.

- **The benign corpus is too clean.** A benign parse-failure rate of 0.05% is implausibly low for real-world PDFs, since strict parsers reject plenty of legitimate documents. The 97.58% figure is therefore **likely optimistic**, and false positives on unusual but legitimate files would rise in deployment. A benign corpus drawn from the open web is the first priority for future work.
- **Dataset provenance.** Training and test data both draw on Contagio, so overlap cannot be fully excluded. Records are de-duplicated by SHA-256 and coverage is reported for this reason.
- **Static analysis only.** Files are inspected without being executed, so behaviour that only appears when a document is opened is out of scope.
- **Malformed files are flagged `suspicious`, not `malicious`.** This is deliberate: the system will not assert malice about a file it could not fully inspect. It flags, contains and explains instead of guessing.

---

## How it works

A PDF enters through one of two doors — the Chrome extension captures it automatically, or a user uploads it to the dashboard — and both feed the same pipeline.

```
PDF  ──►  Parser  ──►  32 structural features  ──►  ┌─ Logistic Regression model
                │                                    └─ Rule engine
                │                                              │
                │                                              ▼
                └── parse failure ──► critical signal ──► Fusion ──► verdict
                                                                     confidence
                                                                     explanations
```

**Verdict logic**

- The model returns a malicious probability via the sigmoid function.
- The rule engine returns a score and a severity, plus the specific rules that triggered.
- A parse failure raises `malformed-pdf-structure` at **critical** severity.
- The fusion layer combines these into `benign`, `suspicious` or `malicious`, with a confidence score and plain-English reasons.

**Why Logistic Regression and not an ensemble?** Because every verdict traces directly to a feature multiplied by a learned weight. The model is interpretable *by construction*, rather than having SHAP or LIME bolted on afterwards. That is a deliberate trade of a little raw accuracy for genuine explainability.

**Why 32 features and not 100?** The 32 are security-critical — JavaScript, OpenAction, EmbeddedFile, encryption, keyword counts, page count, file size. Fonts and layout carry no security signal, and adding them would add noise. Broadening the feature set is identified as future work.

---

## Features

- **Chrome extension** — scans PDFs at the browser, before they are opened
- **Streamlit dashboard** — single-file analysis, two-file comparison, batch review, ZIP intake
- **Explainable verdicts** — every decision comes with the rules that fired and why
- **Safe reader** — malicious and suspicious files are contained; full preview requires explicit override
- **Forensic exports** — forensic report, PDF report, CSV summary
- **Analyst review** — review status, priority, disposition and notes per file
- **Persistent scan history** — SHA-256 recorded per scan for provenance

---

## Running it locally

Requires **Python 3.13**.

**1. Clone and set up the environment**

```bash
git clone https://github.com/okonjigoodnews/advanced-pdf-safescan.git
cd advanced-pdf-safescan

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

**2. Run the dashboard**

```bash
streamlit run app/ui_streamlit.py
```

**3. Run the backend API** (needed by the Chrome extension)

```bash
python -m app.api_server --host 127.0.0.1 --port 8008
```

The dashboard and the API are deployed as **two separate Render services**. The extension talks to the API, not to Streamlit.

**Environment variables**

| Variable | Purpose |
|---|---|
| `API_AUTH_TOKEN` | Bearer token for the backend API |
| `APP_PUBLIC_BASE_URL` | Public base URL used to build shareable links |

Never commit real token values. Use a local `.env` or your Render environment settings.

---

## Project structure

```
app/
  api_server.py        # backend API consumed by the Chrome extension
  main.py              # analysis orchestration (run_pdf_analysis_details)
  runtime_config.py    # API token header configuration
  ui_streamlit.py      # Streamlit dashboard
src/
  ml/
    classifier.py      # MalwareClassifier, model loading
  parser/
    document_parser.py # PDF parsing, raises PDFParserError on malformed files
  reporting/
    comparison.py      # two-file comparison summary
    csv_export.py      # CSV summary export
    explanations.py    # explanation panel construction
    forensics.py       # forensic report, SHA-256, recommendations
    history.py         # persistent scan history
    pdf_export.py      # PDF report export
    pdf_reader.py      # SafePDFReader, contained preview
    review_notes.py    # analyst review notes
    summary.py         # analysis summary
    zip_ingest.py      # ZIP archive intake
```

---

## Testing

```bash
pytest
```

138 tests currently pass, covering the rule normalisation fix and the fusion gating fix.

---

## Academic context

This work sits alongside recent published research on PDF malware detection.

| System | Approach | Accuracy | Coverage reported? |
|---|---|---|---|
| Hossain et al. (2024) | Random Forest, explainable | ~96–97% | No |
| Elattar et al. (2024) | Gradient boosting, SHAP | ~99.9% | No |
| Nguyen et al. (2025) | Stacked ensemble | ~97% | No |
| **Advanced PDFSafeScan** | Hybrid, explainable, deployed | **97.58% end-to-end** | **Yes — 100%** |

Note the final column. If two thirds of malicious PDFs fail to parse, an unreported coverage figure may be concealing the same gap this project found in its own system. **Coverage should be reported as standard.** That is the contribution this work offers the field.

---

## Licence and use

Academic project submitted in partial fulfilment of an MSc in Cyber Security. Malware samples are not distributed with this repository.
