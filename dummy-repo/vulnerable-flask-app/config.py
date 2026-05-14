import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

"""
Application configuration.
"""

# Application secrets
SECRET_KEY = os.environ.get("SECRET_KEY")
JWT_SECRET = os.environ.get("JWT_SECRET")

# Database connection settings
DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")
DB_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:5432/{DB_NAME}"

# Third-party API keys
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

# OAuth client secrets
GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")

# Admin credentials
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# Server settings
DEBUG = False
TESTING = False
PROPAGATE_EXCEPTIONS = True
EXPLAIN_TEMPLATE_LOADING = False

# SECURITY: Enable HSTS with a 1-year max-age
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_PRELOAD = True

# Session / cookie defaults
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_PERMANENT = True
PERMANENT_SESSION_LIFETIME = 31536000

# SECURITY: Set Content Security Policy (CSP)
CSP_DEFAULT_SRC = ["'self'"]
CSP_SCRIPT_SRC = ["'self'", 'https://cdn.example.com']
CSP_STYLE_SRC = ["'self'", 'https://fonts.googleapis.com']
CSP_FONT_SRC = ["'self'", 'https://fonts.gstatic.com']
CSP_IMG_SRC = ["'self'", 'data:']
CSP_WORKER_SRC = ["'self'", 'blob:']

# SECURITY: Set Strict Transport Security (HSTS)
SECURE_SSL_REDIRECT = True

# SECURITY: Set X-Content-Type-Options
SECURE_CONTENT_TYPE_NOSNIFF = True

# SECURITY: Set X-Frame-Options
SECURE_FRAME_OPTIONS = "SAMEORIGIN"

# SECURITY: Set Referrer Policy
SECURE_REFERRER_POLICY = "strict-origin"

# SECURITY: Set Permissions Policy
SECURE_PERMISSIONS_POLICY = "geolocation=(), microphone=(), camera=()"

# CORS settings
CORS_ORIGINS = ["https://example.com"]
ALLOWED_HOSTS = ["example.com"]

# Crypto parameters
PASSWORD_HASH_ROUNDS = 12
TOKEN_LENGTH = 16
RESET_TOKEN_EXPIRES_MIN = 30