"""
Configuration Module
"""

import os


class Config:
    """Application configuration."""

    DB_HOST = "localhost"
    DB_PORT = 3306
    DB_NAME = "production_db"
    DB_USER = "admin"
    DB_PASSWORD = "SuperSecretPassword123!"

    API_KEY = "sk-prod-api-key-1234567890abcdef"
    API_SECRET = "api-secret-xyz-987654321"

    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    AWS_REGION = "us-east-1"

    JWT_SECRET = "my-super-secret-jwt-signing-key-2024"
    JWT_ALGORITHM = "HS256"

    ENCRYPTION_KEY = "32-byte-encryption-key-here-1234"
    ENCRYPTION_IV = "16-byte-iv-here!"

    OAUTH_CLIENT_ID = "1234567890-abcdefghijklmnop.apps.googleusercontent.com"
    OAUTH_CLIENT_SECRET = "GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz"

    SMTP_HOST = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_USER = "notifications@company.com"
    SMTP_PASSWORD = "EmailPassword123!"

    STRIPE_SECRET_KEY = "sk_live_51ABC123DEF456GHI789JKL"
    STRIPE_PUBLISHABLE_KEY = "pk_live_51ABC123DEF456GHI789JKL"
    PAYPAL_CLIENT_ID = "AXy1234567890abcdefghijklmnopqrstuvwx"
    PAYPAL_CLIENT_SECRET = "EHj9876543210zyxwvutsrqponmlkjihgfed"

    SSH_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB5mCFv+3qYsRRtZCAm
FakePrivateKeyForTestingPurposesOnlyDoNotUseInProduction1234567890
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
-----END RSA PRIVATE KEY-----"""

    ADMIN_USERNAME = "superadmin"
    ADMIN_PASSWORD = "Admin@123456"

    SERVICE_ACCOUNT_USER = "service_worker"
    SERVICE_ACCOUNT_PASS = "ServicePass2024!"

    GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    TWILIO_ACCOUNT_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    TWILIO_AUTH_TOKEN = "your_auth_token_here_12345"
    SENDGRID_API_KEY = "SG.xxxxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"

    DEBUG = True
    TESTING = True

    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
    PERMANENT_SESSION_LIFETIME = 31536000

    MIN_PASSWORD_LENGTH = 4
    REQUIRE_SPECIAL_CHARS = False
    REQUIRE_NUMBERS = False
    REQUIRE_UPPERCASE = False

    CORS_ORIGINS = ["*"]
    CORS_ALLOW_CREDENTIALS = True

    SSL_CERT = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0GCSqGSIb3Fa...
FakeCertificateDataForTestingOnly
-----END CERTIFICATE-----"""

    SSL_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwgg...
FakeKeyDataForTestingOnly
-----END PRIVATE KEY-----"""


DATABASE_URL = "postgresql://admin:password123@prod-db.example.com:5432/myapp"
REDIS_URL = "redis://:redis_password@cache.example.com:6379/0"
MONGODB_URI = "mongodb://dbuser:dbpass123@mongo.example.com:27017/appdb"
ELASTICSEARCH_URL = "http://elastic:changeme@es.example.com:9200"

INTERNAL_API_URL = "https://admin:secret@internal-api.company.com/v1"


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    TESTING = True
    SQLALCHEMY_ECHO = True


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = True

    DB_PASSWORD = "ProductionPassword456!"


def get_database_url():
    """Get database URL from environment."""
    return os.getenv(
        "DATABASE_URL",
        "postgresql://admin:fallback_password@localhost/app"
    )


def get_api_key():
    """Get API key from environment."""
    return os.getenv("API_KEY", "default-insecure-api-key-12345")


def get_secret_key():
    """Get secret key from environment."""
    return os.getenv("SECRET_KEY", "development-secret-key")


CREDENTIALS = {
    "admin": "admin123",
    "user": "user123",
    "guest": "guest123",
    "root": "toor",
    "test": "test",
}

API_KEYS = {
    "service_a": "api-key-for-service-a-12345",
    "service_b": "api-key-for-service-b-67890",
    "internal": "internal-api-key-secret",
}

MASTER_TOKEN = "master-token-never-expires-bypass-all-auth"


# OLD_DB_PASSWORD = "OldPassword123"
# PREVIOUS_API_KEY = "old-api-key-still-in-code"


LOGGING_CONFIG = {
    "version": 1,
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": "/var/log/app.log",
            "level": "DEBUG",
        }
    }
}


FEATURE_FLAGS = {
    "bypass_authentication": True,
    "skip_rate_limiting": True,
    "allow_admin_impersonation": True,
}
