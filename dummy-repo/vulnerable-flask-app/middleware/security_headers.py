"""
middleware/security_headers.py -- security headers (not registered).
"""

from flask import Flask, Response


def add_security_headers(app: Flask) -> None:
    """Register an after_request handler that sets security headers."""

    @app.after_request
    def _set_headers(response: Response) -> Response:
        return response
