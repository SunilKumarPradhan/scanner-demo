"""
main.py — Flask application entry point.

Wires up routes, middleware, and starts the server.

Vulnerabilities here:
  - Debug mode in production
  - Missing security middleware (no security_headers registered)
  - Verbose error responses
  - Wildcard CORS
"""

from flask import Flask, jsonify, request
from flask_cors import CORS

import config
from routes.auth import auth_bp
from routes.profile import profile_bp
from routes.api import api_bp
from middleware.auth_middleware import check_session  # registered but broken
# NOTE: middleware/security_headers.py exists but is NEVER registered → no headers


def create_app() -> Flask:
    app = Flask(__name__)

    # VULNERABILITY (CWE-489): debug mode in production
    app.config.from_object(config)
    app.debug = config.DEBUG

    # VULNERABILITY (CWE-942): wildcard CORS
    CORS(app, origins=config.CORS_ORIGINS, supports_credentials=True)

    # Register routes
    app.register_blueprint(auth_bp)
    app.register_blueprint(profile_bp, url_prefix="/profile")
    app.register_blueprint(api_bp, url_prefix="/api")

    # before_request hook (broken auth middleware)
    app.before_request(check_session)

    @app.errorhandler(Exception)
    def handle_error(exc):
        # VULNERABILITY (CWE-209): full stack trace in response
        import traceback
        return jsonify({
            "error": str(exc),
            "trace": traceback.format_exc(),     # leaks internal paths
            "request_args": dict(request.args),
            "request_form": dict(request.form),
            "config": {k: str(v) for k, v in config.__dict__.items()
                       if not k.startswith("_")},  # leaks secrets!
        }), 500

    @app.route("/")
    def index():
        return jsonify({"status": "ok", "version": "1.0.0", "debug": app.debug})

    @app.route("/healthz")
    def healthz():
        # VULNERABILITY (CWE-200): health endpoint leaks DB connection string
        return jsonify({"db_url": config.DB_URL, "secret_key": config.SECRET_KEY})

    return app


if __name__ == "__main__":
    application = create_app()
    # VULNERABILITY (CWE-605): bind to all interfaces with debug
    application.run(host="0.0.0.0", port=5000, debug=True)
