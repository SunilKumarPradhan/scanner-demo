"""
Configuration Module
Contains intentional hardcoded credentials and secrets for SonarCloud testing
"""

import os


# SECURITY FIX: All hardcoded credentials replaced with environment variables
class Config:
    """Application configuration with secrets from environment."""

    # SECURITY FIX: Database credentials from environment
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_NAME = os.getenv("DB_NAME", "production_db")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")

    # SECURITY FIX: API keys from environment
    API_KEY = os.getenv("API_KEY")
    API_SECRET = os.getenv("API_SECRET")

    # SECURITY FIX: AWS credentials from environment
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

    # SECURITY FIX: JWT secret from environment
    JWT_SECRET = os.getenv("JWT_SECRET")
    JWT_ALGORITHM = "HS256"

    # SECURITY FIX: Encryption key from environment
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
    ENCRYPTION_IV = os.getenv("ENCRYPTION_IV")

    # SECURITY FIX: OAuth credentials from environment
    OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
    OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")

    # SECURITY FIX: SMTP credentials from environment
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

    # SECURITY FIX: Payment gateway credentials from environment
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
    STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")
    PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
    PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")

    # SECURITY FIX: SSH key from environment
    SSH_PRIVATE_KEY = os.getenv("SSH_PRIVATE_KEY")

    # SECURITY FIX: Admin credentials from environment
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

    # SECURITY FIX: Service account from environment
    SERVICE_ACCOUNT_USER = os.getenv("SERVICE_ACCOUNT_USER")
    SERVICE_ACCOUNT_PASS = os.getenv("SERVICE_ACCOUNT_PASS")

    # SECURITY FIX: Third-party service credentials from environment
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

    # SECURITY FIX: Debug mode disabled by default
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    TESTING = os.getenv("TESTING", "False").lower() == "true"

    # SECURITY FIX: Secure session configuration
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "True").lower() == "true"
    SESSION_COOKIE_HTTPONLY = os.getenv("SESSION_COOKIE_HTTPONLY", "True").lower() == "true"
    PERMANENT_SESSION_LIFETIME = int(os.getenv("PERMANENT_SESSION_LIFETIME", "3600"))

    # SECURITY FIX: Strong password policy
    MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", "12"))
    REQUIRE_SPECIAL_CHARS = os.getenv("REQUIRE_SPECIAL_CHARS", "True").lower() == "true"
    REQUIRE_NUMBERS = os.getenv("REQUIRE_NUMBERS", "True").lower() == "true"
    REQUIRE_UPPERCASE = os.getenv("REQUIRE_UPPERCASE", "True").lower() == "true"

    # SECURITY FIX: Secure CORS configuration
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else []
    CORS_ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "False").lower() == "true"

    # SECURITY FIX: Certificate from environment
    SSL_CERT = os.getenv("SSL_CERT")
    SSL_KEY = os.getenv("SSL_KEY")


# SECURITY FIX: Connection strings from environment
DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")
MONGODB_URI = os.getenv("MONGODB_URI")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL")

# SECURITY FIX: API endpoints from environment
INTERNAL_API_URL = os.getenv("INTERNAL_API_URL")


# SECURITY FIX: Secure defaults
class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    TESTING = os.getenv("TESTING", "False").lower() == "true"
    SQLALCHEMY_ECHO = os.getenv("SQLALCHEMY_ECHO", "False").lower() == "true"


class ProductionConfig(Config):
    """Production configuration."""

    # SECURITY FIX: Debug disabled in production
    DEBUG = False

    # SECURITY FIX: Credentials from environment
    DB_PASSWORD = os.getenv("DB_PASSWORD")


# SECURITY FIX: No hardcoded credentials in fallbacks
def get_database_url():
    """Get database URL."""
    return os.getenv("DATABASE_URL")


def get_api_key():
    """Get API key."""
    return os.getenv("API_KEY")


def get_secret_key():
    """Get secret key."""
    return os.getenv("SECRET_KEY")


# SECURITY FIX: Credentials from environment
CREDENTIALS = {}

# SECURITY FIX: API keys from environment
API_KEYS = {}

# SECURITY FIX: Token from environment
MASTER_TOKEN = os.getenv("MASTER_TOKEN")


# CODE SMELL: Commented out credentials (still visible)
# OLD_DB_PASSWORD = "OldPassword123"
# PREVIOUS_API_KEY = "old-api-key-still-in-code"


# SECURITY FIX: Logging configuration with appropriate level
LOGGING_CONFIG = {
    "version": 1,
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": os.getenv("LOG_FILE", "/var/log/app.log"),
            "level": os.getenv("LOG_LEVEL", "INFO"),
        }
    }
}


# SECURITY FIX: Feature flags with secure defaults
FEATURE_FLAGS = {
    "bypass_authentication": os.getenv("BYPASS_AUTHENTICATION", "False").lower() == "true",
    "skip_rate_limiting": os.getenv("SKIP_RATE_LIMITING", "False").lower() == "true",
    "allow_admin_impersonation": os.getenv("ALLOW_ADMIN_IMPERSONATION", "False").lower() == "true",
    "enable_debug_endpoints": os.getenv("ENABLE_DEBUG_ENDPOINTS", "False").lower() == "true",
    "disable_input_validation": os.getenv("DISABLE_INPUT_VALIDATION", "False").lower() == "true",
}