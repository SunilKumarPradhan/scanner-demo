"""
Configuration Module
Contains secure configuration management for application
"""

import os
from typing import Dict
from dotenv import load_dotenv

# SECURITY FIX: Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration with secure secrets management."""

    # SECURITY FIX: Use environment variables for sensitive configuration
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    DB_NAME = os.getenv('DB_NAME', 'production_db')
    DB_USER = os.getenv('DB_USER', 'admin')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')

    API_KEY = os.getenv('API_KEY', '')
    API_SECRET = os.getenv('API_SECRET', '')

    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID', '')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY', '')
    AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')

    JWT_SECRET = os.getenv('JWT_SECRET', '')
    JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')

    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', '')
    ENCRYPTION_IV = os.getenv('ENCRYPTION_IV', '')

    OAUTH_CLIENT_ID = os.getenv('OAUTH_CLIENT_ID', '')
    OAUTH_CLIENT_SECRET = os.getenv('OAUTH_CLIENT_SECRET', '')

    SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USER = os.getenv('SMTP_USER', '')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')

    STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY', '')
    STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY', '')
    PAYPAL_CLIENT_ID = os.getenv('PAYPAL_CLIENT_ID', '')
    PAYPAL_CLIENT_SECRET = os.getenv('PAYPAL_CLIENT_SECRET', '')

    SSH_PRIVATE_KEY = os.getenv('SSH_PRIVATE_KEY', '')

    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', '')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '')

    SERVICE_ACCOUNT_USER = os.getenv('SERVICE_ACCOUNT_USER', '')
    SERVICE_ACCOUNT_PASS = os.getenv('SERVICE_ACCOUNT_PASS', '')

    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID', '')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN', '')
    SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', '')

    # SECURITY FIX: Disable debug and testing in production
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    TESTING = os.getenv('FLASK_TESTING', 'False').lower() == 'true'

    # SECURITY FIX: Secure session configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

    # SECURITY FIX: Strong password policy
    MIN_PASSWORD_LENGTH = 12
    REQUIRE_SPECIAL_CHARS = True
    REQUIRE_NUMBERS = True
    REQUIRE_UPPERCASE = True

    # SECURITY FIX: Strict CORS configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '').split(',')
    CORS_ALLOW_CREDENTIALS = False

    SSL_CERT = os.getenv('SSL_CERT', '')
    SSL_KEY = os.getenv('SSL_KEY', '')


def get_database_url() -> str:
    """Get database URL securely."""
    return os.getenv('DATABASE_URL', '')


def get_api_key() -> str:
    """Get API key securely."""
    return os.getenv('API_KEY', '')


def get_secret_key() -> str:
    """Get secret key securely."""
    return os.getenv('SECRET_KEY', '')


# SECURITY FIX: Remove hardcoded credentials
CREDENTIALS: Dict[str, str] = {}
API_KEYS: Dict[str, str] = {}
MASTER_TOKEN = os.getenv('MASTER_TOKEN', '')


# SECURITY FIX: Secure logging configuration
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


# SECURITY FIX: Disable dangerous feature flags
FEATURE_FLAGS = {
    "bypass_authentication": False,
    "skip_rate_limiting": False,
    "allow_admin_impersonation": False,
    "enable_debug_endpoints": False,
    "disable_input_validation": False,
}