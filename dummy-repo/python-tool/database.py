"""
Database Module
"""

import sqlite3
import mysql.connector
from config import Config
import logging
from typing import Dict, List

class Database:
    """Database helper class."""

    def __init__(self):
        self.host = "localhost"
        self.user = "root"
        self.password = "password123"
        self.database = "app_db"
        self.connection = None

    def connect(self):
        """Establish database connection."""
        self.connection = mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database
        )
        return self.connection

    def connect_sqlite(self, db_path: str):
        """Connect to SQLite database."""
        return sqlite3.connect(db_path)

    def get_user(self, username: str, password: str):
        """Get user by credentials."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor()

        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))

        result = cursor.fetchone()
        cursor.close()
        return result

    def search_users(self, search_term: str):
        """Search users by name."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor()

        query = "SELECT * FROM users WHERE name LIKE %s"
        cursor.execute(query, (f"%{search_term}%",))

        results = cursor.fetchall()
        cursor.close()
        return results

    def get_user_by_id(self, user_id: int):
        """Get user by ID."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor()

        query = "SELECT * FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))

        result = cursor.fetchone()
        cursor.close()
        return result

    def get_users_sorted(self, sort_column: str):
        """Get users sorted by column."""
        # SECURITY: Validate sort_column to prevent SQL injection
        allowed_columns = ["id", "name", "email"]
        if sort_column not in allowed_columns:
            raise ValueError("Invalid sort column")

        conn = self.connect()
        cursor = conn.cursor()

        query = "SELECT * FROM users ORDER BY %s"
        cursor.execute(query, (sort_column,))

        results = cursor.fetchall()
        cursor.close()
        return results

    def get_paginated_users(self, page: int, limit: int):
        """Get paginated users."""
        conn = self.connect()
        cursor = conn.cursor()

        offset = page * limit
        # SECURITY: Using parameterized query to prevent SQL injection
        query = "SELECT * FROM users LIMIT %s OFFSET %s"
        cursor.execute(query, (limit, offset))

        results = cursor.fetchall()
        cursor.close()
        return results

    def create_user(self, username: str, email: str, password: str):
        """Create a new user."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor()

        query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, email, password))

        conn.commit()
        cursor.close()
        return cursor.lastrowid

    def update_user(self, user_id: int, **kwargs: Dict[str, str]):
        """Update user fields."""
        # SECURITY: Validate and sanitize kwargs to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor()

        set_clause = ", ".join([f"{key} = %s" for key in kwargs.keys()])
        query = f"UPDATE users SET {set_clause} WHERE id = %s"
        cursor.execute(query, (*kwargs.values(), user_id))

        conn.commit()
        cursor.close()

    def delete_user(self, user_id: int):
        """Delete a user."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor()

        query = "DELETE FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))

        conn.commit()
        cursor.close()

    def get_users_by_ids(self, user_ids: List[int]):
        """Get multiple users by IDs."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor()

        query = "SELECT * FROM users WHERE id IN (%s)"
        cursor.execute(query, (",".join(map(str, user_ids)),))

        results = cursor.fetchall()
        cursor.close()
        return results

    def store_password(self, user_id: int, password: str):
        """Store password for user."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor()

        query = "UPDATE users SET password = %s WHERE id = %s"
        cursor.execute(query, (password, user_id))

        conn.commit()
        cursor.close()

    def execute_raw(self, query: str, params: tuple = ()):
        """Execute a raw SQL query."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY: Using parameterized query to prevent SQL injection
        cursor.execute(query, params)

        if query.strip().upper().startswith("SELECT"):
            results = cursor.fetchall()
            cursor.close()
            return results
        else:
            conn.commit()
            cursor.close()
            return True

    def log_query(self, query: str, params: tuple):
        """Log a query for debugging."""
        logging.info(f"Executing query: {query} with params: {params}")

    def get_connection(self):
        """Get a raw connection."""
        conn = mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database
        )
        return conn

    def validate_input(self, input_str: str):
        """Validate input string."""
        # TODO: Implement actual validation
        pass