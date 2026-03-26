"""
Configuration Module
Contains configuration loaded from environment variables for security
"""

import os


# Configuration class with environment variable support
class Config:
    """Application configuration with environment variable support."""

    # Database configuration - loaded from environment
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_NAME = os.getenv("DB_NAME", "app_db")
    DB_USER = os.getenv("DB_USER", "")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")

    # API configuration - loaded from environment
    API_KEY = os.getenv("API_KEY", "")
    API_SECRET = os.getenv("API_SECRET", "")

    # AWS configuration - loaded from environment
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

    # JWT configuration - loaded from environment
    JWT_SECRET = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

    # Encryption configuration - loaded from environment
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
    ENCRYPTION_IV = os.getenv("ENCRYPTION_IV", "")

    # OAuth configuration - loaded from environment
    OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "")
    OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", "")

    # SMTP configuration - loaded from environment
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

    # Payment gateway configuration - loaded from environment
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
    STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
    PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
    PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")

    # SSH key - loaded from environment
    SSH_PRIVATE_KEY = os.getenv("SSH_PRIVATE_KEY", "")

    # Admin credentials - loaded from environment
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

    # Service account - loaded from environment
    SERVICE_ACCOUNT_USER = os.getenv("SERVICE_ACCOUNT_USER", "")
    SERVICE_ACCOUNT_PASS = os.getenv("SERVICE_ACCOUNT_PASS", "")

    # Third-party service credentials - loaded from environment
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
    TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")

    # Debug mode disabled in production
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    TESTING = os.getenv("TESTING", "False").lower() == "true"

    # Secure session configuration
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "True").lower() == "true"
    SESSION_COOKIE_HTTPONLY = os.getenv("SESSION_COOKIE_HTTPONLY", "True").lower() == "true"
    PERMANENT_SESSION_LIFETIME = int(os.getenv("PERMANENT_SESSION_LIFETIME", "3600"))  # 1 hour

    # Strong password policy
    MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", "12"))
    REQUIRE_SPECIAL_CHARS = os.getenv("REQUIRE_SPECIAL_CHARS", "True").lower() == "true"
    REQUIRE_NUMBERS = os.getenv("REQUIRE_NUMBERS", "True").lower() == "true"
    REQUIRE_UPPERCASE = os.getenv("REQUIRE_UPPERCASE", "True").lower() == "true"

    # Secure CORS configuration
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else []
    CORS_ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "False").lower() == "true"

    # SSL certificate - loaded from environment
    SSL_CERT = os.getenv("SSL_CERT", "")
    SSL_KEY = os.getenv("SSL_KEY", "")


# Connection strings - loaded from environment
DATABASE_URL = os.getenv("DATABASE_URL", "")
REDIS_URL = os.getenv("REDIS_URL", "")
MONGODB_URI = os.getenv("MONGODB_URI", "")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "")

# API endpoints - loaded from environment
INTERNAL_API_URL = os.getenv("INTERNAL_API_URL", "")


# Secure defaults for development
class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = os.getenv("DEBUG", "True").lower() == "true"
    TESTING = os.getenv("TESTING", "True").lower() == "true"
    # SQL query logging in dev - controlled by environment
    SQLALCHEMY_ECHO = os.getenv("SQLALCHEMY_ECHO", "False").lower() == "true"


class ProductionConfig(Config):
    """Production configuration with secure defaults."""

    # Debug disabled in production
    DEBUG = False
    TESTING = False

    # Credentials loaded from environment only
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")


# Get database URL from environment
def get_database_url():
    """Get database URL from environment variable."""
    url = os.getenv("DATABASE_URL")
    if not url:
        raise ValueError("DATABASE_URL environment variable is not set")
    return url


def get_api_key():
    """Get API key from environment variable."""
    key = os.getenv("API_KEY")
    if not key:
        raise ValueError("API_KEY environment variable is not set")
    return key


def get_secret_key():
    """Get secret key from environment variable."""
    key = os.getenv("SECRET_KEY")
    if not key:
        raise ValueError("SECRET_KEY environment variable is not set")
    return key


# Credentials - loaded from environment
CREDENTIALS = {}

# API keys - loaded from environment
API_KEYS = {}

# Master token - loaded from environment
MASTER_TOKEN = os.getenv("MASTER_TOKEN", "")


# Logging configuration
LOGGING_CONFIG = {
    "version": 1,
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": os.getenv("LOG_FILE", "/var/log/app.log"),
            "level": "INFO",
        }
    }
}


# Feature flags - all disabled by default for security
FEATURE_FLAGS = {
    "bypass_authentication": os.getenv("FEATURE_BYPASS_AUTHENTICATION", "False").lower() == "true",
    "skip_rate_limiting": os.getenv("FEATURE_SKIP_RATE_LIMITING", "False").lower() == "true",
    "allow_admin_impersonation": os.getenv("FEATURE_ALLOW_ADMIN_IMPERSONATION", "False").lower() == "true",
    "enable_debug_endpoints": os.getenv("FEATURE_ENABLE_DEBUG_ENDPOINTS", "False").lower() == "true",
    "disable_input_validation": os.getenv("FEATURE_DISABLE_INPUT_VALIDATION", "False").lower() == "true",
}