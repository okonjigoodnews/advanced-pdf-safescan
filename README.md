# Advanced PDFSafeScan

## Intelligent Malicious PDF Detection with Local Extension API Support

Advanced PDFSafeScan is an MSc cybersecurity project for identifying suspicious and malicious PDF files through layered structural analysis, explainable rule scoring, machine learning classification, and analyst-friendly review workflows.

The project includes:

- a Streamlit analyst dashboard for detailed PDF investigation
- persistent scan history and high-risk review workflows
- analyst notes and review-state tracking
- a lightweight local API server for Chrome extension integration
- a Manifest V3 Chrome extension MVP for PDF link and download scanning

The API server is intentionally localhost-first and designed for demos, dissertation work, and controlled lab use.

## Core Capabilities

### Streamlit Dashboard

- Single-file PDF analysis
- Two-file comparison
- Batch PDF analysis
- ZIP upload support
- Explanation panel and triggered-rule reporting
- Safe Reader controls
- Persistent scan history with search and export
- High-risk and quarantine workflow tables
- Analyst notes, review status, priority, and disposition tracking
- Forensic JSON and PDF reporting
- Live status strip and risk trend charts

### Local Extension API

- `GET /api/health`
- `GET /api/scan/recent`
- `POST /api/scan/file`
- `POST /api/scan/url`
- Cache-aware SHA-256 scan reuse from existing history
- Reuse of analyst review metadata in extension-facing responses
- JSON-only responses suitable for a local Chrome extension bridge

### Chrome Extension MVP

- Right-click PDF link scanning
- Scan current PDF from the popup
- Popup latest result and recent scan history
- Options page for backend and notification settings
- Automatic downloaded PDF scanning using the Chrome downloads API
- Local-first integration with the existing API server

## Project Structure

```text
advanced-pdf-safescan/
|-- app/
|   |-- api_server.py
|   |-- cli.py
|   |-- main.py
|   `-- ui_streamlit.py
|-- data/
|-- models/
|-- src/
|   |-- reporting/
|   |   |-- extension_bridge.py
|   |   |-- history.py
|   |   `-- review_notes.py
|   `-- ...
|-- tests/
|   |-- test_api_server.py
|   |-- test_extension_bridge.py
|   `-- ...
`-- README.md
