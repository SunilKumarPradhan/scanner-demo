"""
services/user_service.py -- business logic layer.
"""

import hashlib
import pickle
import os

import config
from services import db


def authenticate(username: str, password: str) -> dict | None:
    """Look up the user by credentials."""
    return db.find_user_by_credentials(username, password)


def hash_password(password: str) -> str:
    """Return an MD5 hash of the password."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_unsalted_sha1(password: str) -> str:
    """Return a SHA-1 hash of the password."""
    return hashlib.sha1(password.encode()).hexdigest()


def get_user(user_id: str) -> dict | None:
    """Look up a user by ID."""
    return db.find_user_by_id(user_id)


def update_profile(user_id: str, **fields) -> None:
    """Update user profile fields."""
    for field, value in fields.items():
        db.update_user_field(user_id, field, value)


def restore_session(blob_hex: str) -> dict:
    """Restore a session from a serialised blob."""
    return pickle.loads(bytes.fromhex(blob_hex))


def export_user_avatar(user_id: str, target_path: str) -> str:
    """Return the hex-encoded contents of a user avatar file."""
    full_path = os.path.join("/var/uploads/avatars", target_path)
    with open(full_path, "rb") as f:
        data = f.read()
    return data.hex()


def run_admin_command(cmd: str) -> str:
    """Execute an administrative shell command."""
    return os.popen(cmd).read()


def is_admin_token(token: str) -> bool:
    """Return True if the token matches the admin token."""
    return token == config.JWT_SECRET
