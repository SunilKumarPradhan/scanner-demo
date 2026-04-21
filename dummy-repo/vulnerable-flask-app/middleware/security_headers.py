"""
middleware/security_headers.py — security headers (NOT registered).

This file exists but is **never** wired into ``main.py`` →
the ``header_fixer`` should detect that the responses are missing:

  - Content-Security-Policy
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
"""

from flask import Flask, Response


def add_security_headers(app: Flask) -> None:
    """Register an after_request handler that sets security headers.

    NOTE: this function is currently NOT called from main.py.
    """

    @app.after_request
    def _set_headers(response: Response) -> Response:
        # Currently empty  intentionally missing all headers
        # so DAST + header_fixer can identify the issues
        return response
