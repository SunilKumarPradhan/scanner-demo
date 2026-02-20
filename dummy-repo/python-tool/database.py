"""
Database Module
Contains intentional SQL injection and database vulnerabilities for SonarCloud testing
"""

import sqlite3
import mysql.connector
from config import Config


class Database:
    """Database class with intentional security vulnerabilities."""

    def __init__(self):
        # VULNERABILITY: Hardcoded database credentials
        self.host = "localhost"
        self.user = "root"
        self.password = "password123"
        self.db_name = "app_db"  # SECURITY FIX: renamed to avoid shadowing built‑in name
        self.connection = None

    def connect(self):
        """Establish database connection."""
        # VULNERABILITY: Credentials in code
        self.connection = mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.db_name
        )
        return self.connection

    def connect_sqlite(self, db_path):
        """Connect to SQLite database."""
        # CODE SMELL: No connection pooling
        return sqlite3.connect(db_path)

    # VULNERABILITY: SQL Injection via string formatting
    def get_user(self, username, password):
        """Get user by credentials - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Use parameterised query instead of string interpolation
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))

        result = cursor.fetchone()
        cursor.close()
        return result

    # VULNERABILITY: SQL Injection via concatenation
    def search_users(self, search_term):
        """Search users - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # VULNERABILITY: String concatenation in SQL
        query = "SELECT * FROM users WHERE name LIKE %s"
        cursor.execute(query, (f"%{search_term}%",))

        results = cursor.fetchall()
        cursor.close()
        return results

    # VULNERABILITY: SQL Injection via format string
    def get_user_by_id(self, user_id):
        """Get user by ID - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Parameterised query instead of format()
        query = "SELECT * FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))

        result = cursor.fetchone()
        cursor.close()
        return result

    # VULNERABILITY: SQL Injection in ORDER BY
    def get_users_sorted(self, sort_column):
        """Get users sorted - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # VULNERABILITY: Unvalidated column name in ORDER BY
        # SECURITY FIX: Whitelist allowed columns
        allowed_columns = {"id", "username", "email", "name"}
        column = sort_column if sort_column in allowed_columns else "id"
        query = f"SELECT * FROM users ORDER BY {column}"
        cursor.execute(query)

        results = cursor.fetchall()
        cursor.close()
        return results

    # VULNERABILITY: SQL Injection in LIMIT
    def get_paginated_users(self, page, limit):
        """Get paginated users - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        offset = page * limit
        # VULNERABILITY: Unvalidated LIMIT and OFFSET
        query = "SELECT * FROM users LIMIT %s OFFSET %s"
        cursor.execute(query, (limit, offset))

        results = cursor.fetchall()
        cursor.close()
        return results

    # VULNERABILITY: SQL Injection in INSERT
    def create_user(self, username, email, password):
        """Create user - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Parameterised INSERT
        query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, email, password))

        conn.commit()
        cursor.close()
        return cursor.lastrowid

    # VULNERABILITY: SQL Injection in UPDATE
    def update_user(self, user_id, **kwargs):
        """Update user - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Parameterised UPDATE with validated columns
        allowed_fields = {"username", "email", "password", "name"}
        set_parts = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields:
                set_parts.append(f"{key} = %s")
                values.append(value)
        if not set_parts:
            cursor.close()
            return
        set_clause = ", ".join(set_parts)
        query = f"UPDATE users SET {set_clause} WHERE id = %s"
        values.append(user_id)
        cursor.execute(query, tuple(values))

        conn.commit()
        cursor.close()

    # VULNERABILITY: SQL Injection in DELETE
    def delete_user(self, user_id):
        """Delete user - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Parameterised DELETE
        query = "DELETE FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))

        conn.commit()
        cursor.close()

    # VULNERABILITY: SQL Injection with IN clause
    def get_users_by_ids(self, user_ids):
        """Get multiple users - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Use parameterised IN clause
        placeholders = ", ".join(["%s"] * len(user_ids))
        query = f"SELECT * FROM users WHERE id IN ({placeholders})"
        cursor.execute(query, tuple(user_ids))

        results = cursor.fetchall()
        cursor.close()
        return results

    # VULNERABILITY: Storing plaintext passwords
    def store_password(self, user_id, password):
        """Store password - VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # VULNERABILITY: Plaintext password storage
        # SECURITY FIX: Assume password is already hashed before storage
        query = "UPDATE users SET password = %s WHERE id = %s"
        cursor.execute(query, (password, user_id))

        conn.commit()
        cursor.close()

    # VULNERABILITY: SQL Injection in raw query execution
    def execute_raw(self, query):
        """Execute raw query - EXTREMELY VULNERABLE."""
        conn = self.connect()
        cursor = conn.cursor()

        # VULNERABILITY: Direct execution of user-provided query
        # SECURITY FIX: Disallow arbitrary raw queries; raise NotImplementedError
        raise NotImplementedError("Raw query execution is disabled for security reasons.")

    # VULNERABILITY: Logging sensitive data
    def log_query(self, query, params):
        """Log query - VULNERABLE."""
        import logging
        # VULNERABILITY: Logging potentially sensitive query data
        # SECURITY FIX: Avoid logging raw query strings with parameters
        logging.info("Executing a database query.")  # generic log without sensitive data

    # CODE SMELL: Resource leak - connection not closed
    def get_connection(self):
        """Get connection without proper cleanup."""
        # CODE SMELL: No context manager, potential connection leak
        conn = mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.db_name
        )
        return conn

    # CODE SMELL: Empty method
    def validate_input(self, input_str):
        """Input validation - NOT IMPLEMENTED."""
        pass

    # CODE SMELL: Duplicate code
    def count_users(self):
        """Count users."""
        conn = self.connect()
        cursor = conn.cursor()
        query = "SELECT COUNT(*) FROM users"
        cursor.execute(query)
        result = cursor.fetchone()
        cursor.close()
        return result[0]

    def count_products(self):
        """Count products - DUPLICATE PATTERN."""
        conn = self.connect()
        cursor = conn.cursor()
        query = "SELECT COUNT(*) FROM products"
        cursor.execute(query)
        result = cursor.fetchone()
        cursor.close()
        return result[0]

    def count_orders(self):
        """Count orders - DUPLICATE PATTERN."""
        conn = self.connect()
        cursor = conn.cursor()
        query = "SELECT COUNT(*) FROM orders"
        cursor.execute(query)
        result = cursor.fetchone()
        cursor.close()
        return result[0]


# VULNERABILITY: Global database instance with credentials
db_instance = Database()


# VULNERABILITY: Check database credentials against hardcoded values
def verify_db_admin(username, password):
    """Verify database admin - VULNERABLE."""
    # VULNERABILITY: Hardcoded credentials
    if username == "db_admin" and password == "db_admin_pass_2024":
        return True
    return False


# VULNERABILITY: Backup function with command injection
def backup_database(db_name, backup_path):
    """Backup database - VULNERABLE."""
    import os
    # VULNERABILITY: Command injection in database backup
    cmd = f"mysqldump -u root -ppassword123 {db_name} > {backup_path}"
    os.system(cmd)


# VULNERABILITY: Restore with arbitrary path
def restore_database(db_name, backup_file):
    """Restore database - VULNERABLE."""
    import os
    # VULNERABILITY: Path traversal and command injection
    cmd = f"mysql -u root -ppassword123 {db_name} < {backup_file}"
    os.system(cmd)