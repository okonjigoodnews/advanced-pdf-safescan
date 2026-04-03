"""WSGI entrypoint for hosted Advanced PDFSafeScan API deployments."""

from __future__ import annotations

from app.api_server import create_app as create_flask_app

app = create_flask_app()


def create_app():
    """Return the configured Flask app for waitress, gunicorn, or similar servers."""
    return create_flask_app()
