"""
Configuration with hardcoded secrets and weak defaults.

Vulnerabilities:
  - Hardcoded secret keys (CWE-798)
  - DB credentials in source (CWE-798)
  - Debug enabled in production (CWE-489)
  - Insecure default values
"""

# ─── HARDCODED SECRETS (CWE-798) ───────────────────────────────────
SECRET_KEY = "my-super-secret-flask-key-do-not-share-12345"
JWT_SECRET = "jwt-signing-key-please-keep-private"

# Database credentials in source code
DB_HOST = "prod-db.internal.example.com"
DB_USER = "admin"
DB_PASSWORD = "P@ssw0rd123!"
DB_NAME = "production_db"
DB_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:5432/{DB_NAME}"

# Third-party API keys
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY = "sk_demo_4eC39HqLyjWDarjtT1zdp7dc"
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# OAuth client secrets
GOOGLE_OAUTH_CLIENT_SECRET = "GOCSPX-1234567890abcdefghij"
SLACK_BOT_TOKEN = "xoxb-FAKE-TOKEN-FOR-TESTING-DEMO"

# Hardcoded admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# ─── DEBUG / EXPOSURE ──────────────────────────────────────────────
DEBUG = True
TESTING = True
PROPAGATE_EXCEPTIONS = True
EXPLAIN_TEMPLATE_LOADING = True

# ─── INSECURE DEFAULTS ─────────────────────────────────────────────
SESSION_COOKIE_SECURE = False     # CWE-614 cookie sent over HTTP
SESSION_COOKIE_HTTPONLY = False   # CWE-1004 readable by JS
SESSION_COOKIE_SAMESITE = None    # CWE-352 CSRF
SESSION_PERMANENT = True
PERMANENT_SESSION_LIFETIME = 31536000  # 1 year — way too long

# ─── ALLOWED ORIGINS — wildcards everywhere ────────────────────────
CORS_ORIGINS = ["*"]
ALLOWED_HOSTS = ["*"]

# ─── WEAK CRYPTO PARAMS ────────────────────────────────────────────
PASSWORD_HASH_ROUNDS = 1          # bcrypt rounds way too low
TOKEN_LENGTH = 8                  # short token = brute-forceable
RESET_TOKEN_EXPIRES_MIN = 99999   # tokens never expire
