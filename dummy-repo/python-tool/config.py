"""
Configuration Module
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

class Config:
    """Application configuration."""

    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", 3306))
    DB_NAME = os.getenv("DB_NAME", "production_db")
    DB_USER = os.getenv("DB_USER", "admin")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")

    API_KEY = os.getenv("API_KEY", "")
    API_SECRET = os.getenv("API_SECRET", "")

    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

    JWT_SECRET = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
    ENCRYPTION_IV = os.getenv("ENCRYPTION_IV", "")

    OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "")
    OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", "")

    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER", "notifications@company.com")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
    STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
    PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
    PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")

    SSH_PRIVATE_KEY = os.getenv("SSH_PRIVATE_KEY", "")

    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "superadmin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

    SERVICE_ACCOUNT_USER = os.getenv("SERVICE_ACCOUNT_USER", "service_worker")
    SERVICE_ACCOUNT_PASS = os.getenv("SERVICE_ACCOUNT_PASS", "")

    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
    TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
    SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")

    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    TESTING = os.getenv("TESTING", "False").lower() == "true"

    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"
    SESSION_COOKIE_HTTPONLY = os.getenv("SESSION_COOKIE_HTTPONLY", "True").lower() == "true"
    PERMANENT_SESSION_LIFETIME = int(os.getenv("PERMANENT_SESSION_LIFETIME", 31536000))

    MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", 4))
    REQUIRE_SPECIAL_CHARS = os.getenv("REQUIRE_SPECIAL_CHARS", "False").lower() == "true"
    REQUIRE_NUMBERS = os.getenv("REQUIRE_NUMBERS", "False").lower() == "true"
    REQUIRE_UPPERCASE = os.getenv("REQUIRE_UPPERCASE", "False").lower() == "true"

    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
    CORS_ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "True").lower() == "true"

    SSL_CERT = os.getenv("SSL_CERT", "")
    SSL_KEY = os.getenv("SSL_KEY", "")

    DATABASE_URL = os.getenv("DATABASE_URL", "")
    REDIS_URL = os.getenv("REDIS_URL", "")
    MONGODB_URI = os.getenv("MONGODB_URI", "")
    ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "")

    INTERNAL_API_URL = os.getenv("INTERNAL_API_URL", "")

    CREDENTIALS = {
        "admin": os.getenv("ADMIN_PASSWORD", ""),
        "user": os.getenv("USER_PASSWORD", ""),
        "guest": os.getenv("GUEST_PASSWORD", ""),
        "root": os.getenv("ROOT_PASSWORD", ""),
        "test": os.getenv("TEST_PASSWORD", ""),
    }

    API_KEYS = {
        "service_a": os.getenv("SERVICE_A_API_KEY", ""),
        "service_b": os.getenv("SERVICE_B_API_KEY", ""),
        "internal": os.getenv("INTERNAL_API_KEY", ""),
    }

    MASTER_TOKEN = os.getenv("MASTER_TOKEN", "")

    LOGGING_CONFIG = {
        "version": 1,
        "handlers": {
            "file": {
                "class": RotatingFileHandler,
                "filename": os.getenv("LOG_FILE", "/var/log/app.log"),
                "maxBytes": int(os.getenv("LOG_MAX_BYTES", 10 * 1024 * 1024)),
                "backupCount": int(os.getenv("LOG_BACKUP_COUNT", 10)),
                "level": os.getenv("LOG_LEVEL", "DEBUG"),
            }
        }
    }

    FEATURE_FLAGS = {
        "bypass_authentication": os.getenv("BYPASS_AUTHENTICATION", "False").lower() == "true",
        "skip_rate_limiting": os.getenv("SKIP_RATE_LIMITING", "False").lower() == "true",
        "allow_admin_impersonation": os.getenv("ALLOW_ADMIN_IMPERSONATION", "False").lower() == "true",
    }


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    TESTING = True
    SQLALCHEMY_ECHO = True


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False

    DB_PASSWORD = os.getenv("DB_PASSWORD", "")


def get_database_url():
    """Get database URL from environment."""
    return os.getenv("DATABASE_URL", "")


def get_api_key():
    """Get API key from environment."""
    return os.getenv("API_KEY", "")


def get_secret_key():
    """Get secret key from environment."""
    return os.getenv("SECRET_KEY", "")