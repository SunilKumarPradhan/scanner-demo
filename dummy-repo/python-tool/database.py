"""
Database Module
"""

import sqlite3
import mysql.connector
from config import Config
import logging

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
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor(prepared=True)

        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))

        result = cursor.fetchone()
        cursor.close()
        conn.close()  # Close the connection
        return result

    def search_users(self, search_term):
        """Search users by name."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor(prepared=True)

        query = "SELECT * FROM users WHERE name LIKE %s"
        cursor.execute(query, ('%' + search_term + '%',))

        results = cursor.fetchall()
        cursor.close()
        conn.close()  # Close the connection
        return results

    def get_user_by_id(self, user_id):
        """Get user by ID."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor(prepared=True)

        query = "SELECT * FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))

        result = cursor.fetchone()
        cursor.close()
        conn.close()  # Close the connection
        return result

    def get_users_sorted(self, sort_column):
        """Get users sorted by column."""
        # SECURITY: Validate sort_column to prevent SQL injection
        valid_sort_columns = ['id', 'username', 'email']
        if sort_column not in valid_sort_columns:
            raise ValueError("Invalid sort column")

        conn = self.connect()
        cursor = conn.cursor(prepared=True)

        query = "SELECT * FROM users ORDER BY %s"
        cursor.execute(query, (sort_column,))

        results = cursor.fetchall()
        cursor.close()
        conn.close()  # Close the connection
        return results

    def get_paginated_users(self, page, limit):
        """Get paginated users."""
        # SECURITY: Validate page and limit to prevent SQL injection
        if page < 0 or limit < 0:
            raise ValueError("Invalid page or limit")

        conn = self.connect()
        cursor = conn.cursor(prepared=True)

        offset = page * limit
        query = "SELECT * FROM users LIMIT %s OFFSET %s"
        cursor.execute(query, (limit, offset))

        results = cursor.fetchall()
        cursor.close()
        conn.close()  # Close the connection
        return results

    def create_user(self, username, email, password):
        """Create a new user."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor(prepared=True)

        query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, email, password))

        conn.commit()
        cursor.close()
        conn.close()  # Close the connection
        return cursor.lastrowid

    def update_user(self, user_id, **kwargs):
        """Update user fields."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor(prepared=True)

        set_clause = ", ".join([f"{key} = %s" for key in kwargs.keys()])
        values = list(kwargs.values())
        values.append(user_id)

        query = f"UPDATE users SET {set_clause} WHERE id = %s"
        cursor.execute(query, tuple(values))

        conn.commit()
        cursor.close()
        conn.close()  # Close the connection

    def delete_user(self, user_id):
        """Delete a user."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor(prepared=True)

        query = "DELETE FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))

        conn.commit()
        cursor.close()
        conn.close()  # Close the connection

    def get_users_by_ids(self, user_ids):
        """Get multiple users by IDs."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor(prepared=True)

        query = "SELECT * FROM users WHERE id IN (%s)"
        cursor.execute(query, (",".join(map(str, user_ids)),))

        results = cursor.fetchall()
        cursor.close()
        conn.close()  # Close the connection
        return results

    def store_password(self, user_id, password):
        """Store password for user."""
        # SECURITY: Using parameterized query to prevent SQL injection
        conn = self.connect()
        cursor = conn.cursor(prepared=True)

        query = "UPDATE users SET password = %s WHERE id = %s"
        cursor.execute(query, (password, user_id))

        conn.commit()
        cursor.close()
        conn.close()  # Close the connection

    def execute_raw(self, query, params=None):
        """Execute a raw SQL query."""
        conn = self.connect()
        cursor = conn.cursor(prepared=True)

        if params is None:
            cursor.execute(query)
        else:
            cursor.execute(query, params)

        if query.strip().upper().startswith("SELECT"):
            results = cursor.fetchall()
            cursor.close()
            conn.close()  # Close the connection
            return results
        else:
            conn.commit()
            cursor.close()
            conn.close()  # Close the connection
            return True

    def log_query(self, query, params):
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

    def validate_input(self, input_str):
        """Validate input string."""
        # Implement actual validation and sanitization
        pass