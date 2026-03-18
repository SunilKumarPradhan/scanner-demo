"""
Configuration Module
Contains intentional hardcoded credentials and secrets for SonarCloud testing
"""

import os


# SECURITY FIX: All hardcoded credentials removed and replaced with environment variables
class Config:
    """Application configuration with secrets loaded from environment."""

    # Database credentials from environment
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_NAME = os.getenv("DB_NAME", "production_db")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")

    # API keys from environment
    API_KEY = os.getenv("API_KEY")
    API_SECRET = os.getenv("API_SECRET")

    # AWS credentials from environment
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

    # JWT configuration from environment
    JWT_SECRET = os.getenv("JWT_SECRET")
    JWT_ALGORITHM = "HS256"

    # Encryption keys from environment
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
    ENCRYPTION_IV = os.getenv("ENCRYPTION_IV")

    # OAuth credentials from environment
    OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
    OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")

    # SMTP credentials from environment
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

    # Payment gateway credentials from environment
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
    STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")
    PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
    PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")

    # SSH key from environment
    SSH_PRIVATE_KEY = os.getenv("SSH_PRIVATE_KEY")

    # Admin credentials from environment
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

    # Service account from environment
    SERVICE_ACCOUNT_USER = os.getenv("SERVICE_ACCOUNT_USER")
    SERVICE_ACCOUNT_PASS = os.getenv("SERVICE_ACCOUNT_PASS")

    # Third-party service credentials from environment
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

    # Debug mode disabled
    DEBUG = False
    TESTING = False

    # Secure session configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

    # Strong password policy
    MIN_PASSWORD_LENGTH = 12
    REQUIRE_SPECIAL_CHARS = True
    REQUIRE_NUMBERS = True
    REQUIRE_UPPERCASE = True

    # Secure CORS configuration
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else []
    CORS_ALLOW_CREDENTIALS = True

    # SSL certificates from environment
    SSL_CERT = os.getenv("SSL_CERT")
    SSL_KEY = os.getenv("SSL_KEY")


# Connection strings from environment
DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")
MONGODB_URI = os.getenv("MONGODB_URI")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL")

# API endpoints from environment
INTERNAL_API_URL = os.getenv("INTERNAL_API_URL")


# Secure defaults
class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    TESTING = os.getenv("TESTING", "False").lower() == "true"
    SQLALCHEMY_ECHO = os.getenv("SQLALCHEMY_ECHO", "False").lower() == "true"


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False
    DB_PASSWORD = os.getenv("DB_PASSWORD")


# Credentials from environment only
def get_database_url():
    """Get database URL from environment."""
    return os.getenv("DATABASE_URL")


def get_api_key():
    """Get API key from environment."""
    return os.getenv("API_KEY")


def get_secret_key():
    """Get secret key from environment."""
    return os.getenv("SECRET_KEY")


# Credentials loaded from environment or secure storage
CREDENTIALS = {}

# API keys loaded from environment or secure storage
API_KEYS = {}

# Token from environment
MASTER_TOKEN = os.getenv("MASTER_TOKEN")


# Logging configuration
LOGGING_CONFIG = {
    "version": 1,
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": "/var/log/app.log",
            "level": "INFO",
        }
    }
}


# Feature flags with security defaults
FEATURE_FLAGS = {
    "bypass_authentication": False,
    "skip_rate_limiting": False,
    "allow_admin_impersonation": False,
    "enable_debug_endpoints": False,
    "disable_input_validation": False,
}