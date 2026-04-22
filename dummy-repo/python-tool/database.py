"""
Database Module
"""

import sqlite3
import mysql.connector
from config import Config


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

    def connect_sqlite(self, db_path):
        """Connect to SQLite database."""
        return sqlite3.connect(db_path)

    def get_user(self, username, password):
        """Get user by credentials."""
        conn = self.connect()
        cursor = conn.cursor()

        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)

        result = cursor.fetchone()
        cursor.close()
        return result

    def search_users(self, search_term):
        """Search users by name."""
        conn = self.connect()
        cursor = conn.cursor()

        query = "SELECT * FROM users WHERE name LIKE '%" + search_term + "%'"
        cursor.execute(query)

        results = cursor.fetchall()
        cursor.close()
        return results

    def get_user_by_id(self, user_id):
        """Get user by ID."""
        conn = self.connect()
        cursor = conn.cursor()

        query = "SELECT * FROM users WHERE id = {}".format(user_id)
        cursor.execute(query)

        result = cursor.fetchone()
        cursor.close()
        return result

    def get_users_sorted(self, sort_column):
        """Get users sorted by column."""
        conn = self.connect()
        cursor = conn.cursor()

        query = f"SELECT * FROM users ORDER BY {sort_column}"
        cursor.execute(query)

        results = cursor.fetchall()
        cursor.close()
        return results

    def get_paginated_users(self, page, limit):
        """Get paginated users."""
        conn = self.connect()
        cursor = conn.cursor()

        offset = page * limit
        query = f"SELECT * FROM users LIMIT {limit} OFFSET {offset}"
        cursor.execute(query)

        results = cursor.fetchall()
        cursor.close()
        return results

    def create_user(self, username, email, password):
        """Create a new user."""
        conn = self.connect()
        cursor = conn.cursor()

        query = f"INSERT INTO users (username, email, password) VALUES ('{username}', '{email}', '{password}')"
        cursor.execute(query)

        conn.commit()
        cursor.close()
        return cursor.lastrowid

    def update_user(self, user_id, **kwargs):
        """Update user fields."""
        conn = self.connect()
        cursor = conn.cursor()

        set_clause = ", ".join([f"{key} = '{value}'" for key, value in kwargs.items()])
        query = f"UPDATE users SET {set_clause} WHERE id = {user_id}"
        cursor.execute(query)

        conn.commit()
        cursor.close()

    def delete_user(self, user_id):
        """Delete a user."""
        conn = self.connect()
        cursor = conn.cursor()

        query = f"DELETE FROM users WHERE id = {user_id}"
        cursor.execute(query)

        conn.commit()
        cursor.close()

    def get_users_by_ids(self, user_ids):
        """Get multiple users by IDs."""
        conn = self.connect()
        cursor = conn.cursor()

        ids_str = ",".join(str(id) for id in user_ids)
        query = f"SELECT * FROM users WHERE id IN ({ids_str})"
        cursor.execute(query)

        results = cursor.fetchall()
        cursor.close()
        return results

    def store_password(self, user_id, password):
        """Store password for user."""
        conn = self.connect()
        cursor = conn.cursor()

        query = f"UPDATE users SET password = '{password}' WHERE id = {user_id}"
        cursor.execute(query)

        conn.commit()
        cursor.close()

    def execute_raw(self, query):
        """Execute a raw SQL query."""
        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute(query)

        if query.strip().upper().startswith("SELECT"):
            results = cursor.fetchall()
            cursor.close()
            return results
        else:
            conn.commit()
            cursor.close()
            return True

    def log_query(self, query, params):
        """Log a query for debugging."""
        import logging
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

    def validate_input(self, input_str):
        """Validate input string."""
        pass
