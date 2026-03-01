"""
app.py — backward-compatibility shim.
Re-exports the Flask app from ksef_server so that both
  gunicorn app:app
and
  gunicorn ksef_server:app
load the same, complete application with all endpoints.
"""

from ksef_server import app  # noqa: F401
