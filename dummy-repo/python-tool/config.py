"""
Configuration Module
Contains intentional hardcoded credentials and secrets for SonarCloud testing
"""

import os


# VULNERABILITY: Hardcoded credentials
class Config:
    """Application configuration with hardcoded secrets."""

    # VULNERABILITY: Hardcoded database credentials
    DB_HOST = "localhost"
    DB_PORT = 3306
    DB_NAME = "production_db"
    DB_USER = "admin"
    DB_PASSWORD = "SuperSecretPassword123!"

    # VULNERABILITY: Hardcoded API keys
    API_KEY = "sk-prod-api-key-1234567890abcdef"
    API_SECRET = "api-secret-xyz-987654321"

    # VULNERABILITY: Hardcoded AWS credentials
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    AWS_REGION = "us-east-1"

    # VULNERABILITY: Hardcoded JWT secret
    JWT_SECRET = "my-super-secret-jwt-signing-key-2024"
    JWT_ALGORITHM = "HS256"

    # VULNERABILITY: Hardcoded encryption key
    ENCRYPTION_KEY = "32-byte-encryption-key-here-1234"
    ENCRYPTION_IV = "16-byte-iv-here!"

    # VULNERABILITY: Hardcoded OAuth credentials
    OAUTH_CLIENT_ID = "1234567890-abcdefghijklmnop.apps.googleusercontent.com"
    OAUTH_CLIENT_SECRET = "GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz"

    # VULNERABILITY: Hardcoded SMTP credentials
    SMTP_HOST = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_USER = "notifications@company.com"
    SMTP_PASSWORD = "EmailPassword123!"

    # VULNERABILITY: Hardcoded payment gateway credentials
    STRIPE_SECRET_KEY = "sk_live_51ABC123DEF456GHI789JKL"
    STRIPE_PUBLISHABLE_KEY = "pk_live_51ABC123DEF456GHI789JKL"
    PAYPAL_CLIENT_ID = "AXy1234567890abcdefghijklmnopqrstuvwx"
    PAYPAL_CLIENT_SECRET = "EHj9876543210zyxwvutsrqponmlkjihgfed"

    # VULNERABILITY: Hardcoded SSH key (partial)
    SSH_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB5mCFv+3qYsRRtZCAm
FakePrivateKeyForTestingPurposesOnlyDoNotUseInProduction1234567890
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
-----END RSA PRIVATE KEY-----"""

    # VULNERABILITY: Hardcoded admin credentials
    ADMIN_USERNAME = "superadmin"
    ADMIN_PASSWORD = "Admin@123456"

    # VULNERABILITY: Hardcoded service account
    SERVICE_ACCOUNT_USER = "service_worker"
    SERVICE_ACCOUNT_PASS = "ServicePass2024!"

    # VULNERABILITY: Hardcoded third-party service credentials
    GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    TWILIO_ACCOUNT_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    TWILIO_AUTH_TOKEN = "your_auth_token_here_12345"
    SENDGRID_API_KEY = "SG.xxxxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"

    # VULNERABILITY: Debug mode enabled
    DEBUG = True
    TESTING = True

    # VULNERABILITY: Insecure session configuration
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
    PERMANENT_SESSION_LIFETIME = 31536000  # 1 year - too long

    # VULNERABILITY: Weak password policy
    MIN_PASSWORD_LENGTH = 4  # Too short
    REQUIRE_SPECIAL_CHARS = False
    REQUIRE_NUMBERS = False
    REQUIRE_UPPERCASE = False

    # VULNERABILITY: Insecure CORS configuration
    CORS_ORIGINS = ["*"]  # Allow all origins
    CORS_ALLOW_CREDENTIALS = True

    # VULNERABILITY: Hardcoded certificate
    SSL_CERT = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0GCSqGSIb3Fa...
FakeCertificateDataForTestingOnly
-----END CERTIFICATE-----"""

    SSL_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwgg...
FakeKeyDataForTestingOnly
-----END PRIVATE KEY-----"""


# VULNERABILITY: Hardcoded connection strings
DATABASE_URL = "postgresql://admin:password123@prod-db.example.com:5432/myapp"
REDIS_URL = "redis://:redis_password@cache.example.com:6379/0"
MONGODB_URI = "mongodb://dbuser:dbpass123@mongo.example.com:27017/appdb"
ELASTICSEARCH_URL = "http://elastic:changeme@es.example.com:9200"

# VULNERABILITY: Hardcoded API endpoints with credentials
INTERNAL_API_URL = "https://admin:secret@internal-api.company.com/v1"


# VULNERABILITY: Insecure defaults
class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    TESTING = True
    # VULNERABILITY: SQL query logging in dev
    SQLALCHEMY_ECHO = True


class ProductionConfig(Config):
    """Production configuration - STILL VULNERABLE."""

    # VULNERABILITY: Debug still enabled in production
    DEBUG = True

    # VULNERABILITY: Same hardcoded credentials
    DB_PASSWORD = "ProductionPassword456!"


# VULNERABILITY: Credentials in environment variable defaults
def get_database_url():
    """Get database URL - VULNERABLE."""
    # VULNERABILITY: Fallback to hardcoded credentials
    return os.getenv(
        "DATABASE_URL",
        "postgresql://admin:fallback_password@localhost/app"
    )


def get_api_key():
    """Get API key - VULNERABLE."""
    # VULNERABILITY: Hardcoded fallback
    return os.getenv("API_KEY", "default-insecure-api-key-12345")


def get_secret_key():
    """Get secret key - VULNERABLE."""
    # VULNERABILITY: Predictable default
    return os.getenv("SECRET_KEY", "development-secret-key")


# VULNERABILITY: Credentials dictionary
CREDENTIALS = {
    "admin": "admin123",
    "user": "user123",
    "guest": "guest123",
    "root": "toor",
    "test": "test",
}

# VULNERABILITY: API keys mapping
API_KEYS = {
    "service_a": "api-key-for-service-a-12345",
    "service_b": "api-key-for-service-b-67890",
    "internal": "internal-api-key-secret",
}

# VULNERABILITY: Token with expiry bypass
MASTER_TOKEN = "master-token-never-expires-bypass-all-auth"


# CODE SMELL: Commented out credentials (still visible)
# OLD_DB_PASSWORD = "OldPassword123"
# PREVIOUS_API_KEY = "old-api-key-still-in-code"


# VULNERABILITY: Logging configuration with sensitive data
LOGGING_CONFIG = {
    "version": 1,
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": "/var/log/app.log",
            # VULNERABILITY: Log file might contain sensitive data
            "level": "DEBUG",
        }
    }
}


# VULNERABILITY: Feature flags with security implications
FEATURE_FLAGS = {
    "bypass_authentication": True,  # VULNERABILITY: Auth bypass enabled
    "skip_rate_limiting": True,      # VULNERABILITY: Rate limiting disabled
    "allow_admin_impersonation": True,  # VULNERABILITY: Impersonation allowed
    "enable_debug_endpoints": True,  # VULNERABILITY: Debug endpoints exposed
    "disable_input_validation": True,  # VULNERABILITY: Validation disabled
}
