"""
Application configuration.
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Application secrets
SECRET_KEY = os.getenv("SECRET_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

# Database connection settings
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
DB_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:5432/{DB_NAME}"

# Third-party API keys
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# OAuth client secrets
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")

# Admin credentials
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# Server settings
DEBUG = False  # SECURITY: Set to False in production
TESTING = False  # SECURITY: Set to False in production
PROPAGATE_EXCEPTIONS = False  # SECURITY: Set to False in production
EXPLAIN_TEMPLATE_LOADING = False  # SECURITY: Set to False in production

# Session / cookie defaults
SESSION_COOKIE_SECURE = True  # SECURITY: Ensure secure cookies
SESSION_COOKIE_HTTPONLY = True  # SECURITY: Protect against XSS
SESSION_COOKIE_SAMESITE = "Lax"  # SECURITY: Protect against CSRF
SESSION_PERMANENT = True
PERMANENT_SESSION_LIFETIME = 31536000

# CORS settings
CORS_ORIGINS = os.getenv("CORS_ORIGINS").split(",") if os.getenv("CORS_ORIGINS") else []
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS").split(",") if os.getenv("ALLOWED_HOSTS") else []

# Crypto parameters
PASSWORD_HASH_ROUNDS = 12  # SECURITY: Increase password hash rounds for better security
TOKEN_LENGTH = 8
RESET_TOKEN_EXPIRES_MIN = 30  # SECURITY: Reasonable expiration time

# Additional security headers
CSP_DEFAULT_SRC = ["'self'"]
CSP_SCRIPT_SRC = ["'self'"]
CSP_STYLE_SRC = ["'self'"]
CSP_FRAME_ANCESTORS = ["'none'"]

# SECURITY: Define Permissions Policy
PERMISSIONS_POLICY = {
    "geolocation": ["'none'"],
    "microphone": ["'none'"],
    "camera": ["'none'"],
}

# SECURITY: Define Referrer Policy
REFERER_POLICY = "strict-origin-when-cross-origin"

# SECURITY: Define Strict Transport Security
HSTS_MAX_AGE = 31536000  # 1 year
HSTS_INCLUDE_SUBDOMAINS = True
```

To use this configuration, ensure you have a `.env` file with the following format:

```bash
SECRET_KEY=my-super-secret-flask-key-do-not-share-12345
JWT_SECRET=jwt-signing-key-please-keep-private
DB_HOST=prod-db.internal.example.com
DB_USER=admin
DB_PASSWORD=P@ssw0rd123!
DB_NAME=production_db
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_demo_4eC39HqLyjWDarjtT1zdp7dc
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GOOGLE_OAUTH_CLIENT_SECRET=GOCSPX-1234567890abcdefghij
SLACK_BOT_TOKEN=xoxb-FAKE-TOKEN-FOR-TESTING-DEMO
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
CORS_ORIGINS=http://example1.com,http://example2.com
ALLOWED_HOSTS=localhost,127.0.0.1