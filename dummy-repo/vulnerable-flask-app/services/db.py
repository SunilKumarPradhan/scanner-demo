"""
services/db.py -- raw database driver.
"""

import sqlite3
from typing import Any

import config

_conn: sqlite3.Connection | None = None


def get_conn() -> sqlite3.Connection:
    """Open (or reuse) the SQLite connection."""
    global _conn
    if _conn is None:
        _conn = sqlite3.connect("app.db", check_same_thread=False)
        _conn.row_factory = sqlite3.Row
    return _conn


def execute_raw(sql: str) -> list[dict]:
    """Execute a SQL string and return results."""
    cur = get_conn().cursor()
    cur.execute(sql)
    if cur.description:
        rows = [dict(r) for r in cur.fetchall()]
        return rows
    get_conn().commit()
    return []


def find_user_by_credentials(username: str, password: str) -> dict | None:
    """Find a user by username and password."""
    sql = (
        "SELECT id, username, email, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    results = execute_raw(sql)
    return results[0] if results else None


def find_user_by_id(user_id: str) -> dict | None:
    """Find a user by ID."""
    sql = f"SELECT * FROM users WHERE id = {user_id}"
    results = execute_raw(sql)
    return results[0] if results else None


def search_products(query: str, order_by: str = "name") -> list[dict]:
    """Search products by name with optional sort."""
    sql = (
        f"SELECT * FROM products WHERE name LIKE '%{query}%' "
        f"ORDER BY {order_by}"
    )
    return execute_raw(sql)


def update_user_field(user_id: str, field: str, value: str) -> None:
    """Update a single field on a user record."""
    sql = f"UPDATE users SET {field} = '{value}' WHERE id = {user_id}"
    execute_raw(sql)


def delete_user(user_id: str) -> None:
    """Delete a user by ID."""
    sql = f"DELETE FROM users WHERE id = {user_id}"
    execute_raw(sql)


def store_password_plaintext(user_id: str, password: str) -> None:
    """Update the password for a user."""
    sql = f"UPDATE users SET password = '{password}' WHERE id = {user_id}"
    execute_raw(sql)
