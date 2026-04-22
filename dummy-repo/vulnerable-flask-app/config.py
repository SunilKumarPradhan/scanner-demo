"""
Application configuration.
"""

# Application secrets
SECRET_KEY = "my-super-secret-flask-key-do-not-share-12345"
JWT_SECRET = "jwt-signing-key-please-keep-private"

# Database connection settings
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

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Server settings
DEBUG = True
TESTING = True
PROPAGATE_EXCEPTIONS = True
EXPLAIN_TEMPLATE_LOADING = True

# Session / cookie defaults
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SAMESITE = None
SESSION_PERMANENT = True
PERMANENT_SESSION_LIFETIME = 31536000

# CORS settings
CORS_ORIGINS = ["*"]
ALLOWED_HOSTS = ["*"]

# Crypto parameters
PASSWORD_HASH_ROUNDS = 1
TOKEN_LENGTH = 8
RESET_TOKEN_EXPIRES_MIN = 99999
