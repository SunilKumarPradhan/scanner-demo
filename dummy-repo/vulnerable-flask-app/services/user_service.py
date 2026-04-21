"""
services/user_service.py — business logic layer.

Sits between routes and db.py.  context_gatherer_node should
trace request → route → user_service → db.
"""

import hashlib
import pickle
import os

import config
from services import db


def authenticate(username: str, password: str) -> dict | None:
    """Look up the user by credentials (passes raw input to SQL)."""
    # VULNERABILITY: passes unsanitised input directly to db layer
    return db.find_user_by_credentials(username, password)


def hash_password(password: str) -> str:
    """VULNERABILITY (CWE-327): MD5 is broken."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_unsalted_sha1(password: str) -> str:
    """VULNERABILITY (CWE-916): unsalted SHA-1."""
    return hashlib.sha1(password.encode()).hexdigest()


def get_user(user_id: str) -> dict | None:
    """VULNERABILITY: passes user_id straight through to SQLi sink."""
    return db.find_user_by_id(user_id)


def update_profile(user_id: str, **fields) -> None:
    """VULNERABILITY (CWE-915): mass assignment + SQLi.

    Caller can update ANY field, including ``role`` and ``password``.
    """
    for field, value in fields.items():
        db.update_user_field(user_id, field, value)


def restore_session(blob_hex: str) -> dict:
    """VULNERABILITY (CWE-502): pickle.loads on untrusted input."""
    return pickle.loads(bytes.fromhex(blob_hex))


def export_user_avatar(user_id: str, target_path: str) -> str:
    """VULNERABILITY (CWE-22): path traversal via user-controlled name."""
    full_path = os.path.join("/var/uploads/avatars", target_path)
    with open(full_path, "rb") as f:
        data = f.read()
    return data.hex()


def run_admin_command(cmd: str) -> str:
    """VULNERABILITY (CWE-78): command injection."""
    # Caller passes raw shell string
    return os.popen(cmd).read()


def is_admin_token(token: str) -> bool:
    """VULNERABILITY (CWE-208): non-constant-time comparison."""
    return token == config.JWT_SECRET
