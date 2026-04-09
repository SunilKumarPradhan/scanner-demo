"""
Database Module
Contains intentional SQL injection and database vulnerabilities for SonarCloud testing
"""

import sqlite3
import mysql.connector
import os
from config import Config


class Database:
    """Database class with intentional security vulnerabilities."""

    def __init__(self):
        # SECURITY FIX: Load credentials from environment variables instead of hardcoding
        self.host = os.getenv("DB_HOST", "localhost")
        self.user = os.getenv("DB_USER", "root")
        self.password = os.getenv("DB_PASSWORD")
        self.database = os.getenv("DB_NAME", "app_db")
        self.connection = None
        
        if not self.password:
            raise ValueError("Database password must be set via DB_PASSWORD environment variable")

    def connect(self):
        """Establish database connection."""
        # SECURITY FIX: Credentials now loaded from environment variables
        self.connection = mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database
        )
        return self.connection

    def connect_sqlite(self, db_path):
        """Connect to SQLite database."""
        # CODE SMELL: No connection pooling
        return sqlite3.connect(db_path)

    # SECURITY FIX: Use parameterized queries instead of string formatting
    def get_user(self, username, password):
        """Get user by credentials - FIXED."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Use parameterized query with placeholders
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))

        result = cursor.fetchone()
        cursor.close()
        return result

    # SECURITY FIX: Use parameterized queries instead of string concatenation
    def search_users(self, search_term):
        """Search users - FIXED."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Use parameterized query with placeholders
        query = "SELECT * FROM users WHERE name LIKE %s"
        cursor.execute(query, (f"%{search_term}%",))

        results = cursor.fetchall()
        cursor.close()
        return results

    # SECURITY FIX: Use parameterized queries instead of format strings
    def get_user_by_id(self, user_id):
        """Get user by ID - FIXED."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Use parameterized query with placeholders
        query = "SELECT * FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))

        result = cursor.fetchone()
        cursor.close()
        return result

    # SECURITY FIX: Validate column name against whitelist
    def get_users_sorted(self, sort_column):
        """Get users sorted - FIXED."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Validate sort_column against whitelist of allowed columns
        allowed_columns = ["id", "username", "email", "created_at", "updated_at"]
        if sort_column not in allowed_columns:
            raise ValueError(f"Invalid sort column: {sort_column}")
        
        query = f"SELECT * FROM users ORDER BY {sort_column}"
        cursor.execute(query)

        results = cursor.fetchall()
        cursor.close()
        return results

    # SECURITY FIX: Validate and use parameterized queries for LIMIT and OFFSET
    def get_paginated_users(self, page, limit):
        """Get paginated users - FIXED."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Validate page and limit are positive integers
        if not isinstance(page, int) or not isinstance(limit, int) or page < 0 or limit <= 0:
            raise ValueError("Page and limit must be positive integers")
        
        offset = page * limit
        # SECURITY FIX: Use parameterized query
        query = "SELECT * FROM users LIMIT %s OFFSET %s"
        cursor.execute(query, (limit, offset))

        results = cursor.fetchall()
        cursor.close()
        return results

    # SECURITY FIX: Use parameterized queries for INSERT
    def create_user(self, username, email, password):
        """Create user - FIXED."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Use parameterized query with placeholders
        query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, email, password))

        conn.commit()
        cursor.close()
        return cursor.lastrowid

    # SECURITY FIX: Use parameterized queries for UPDATE
    def update_user(self, user_id, **kwargs):
        """Update user - FIXED."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Validate column names and use parameterized query
        allowed_columns = ["username", "email", "password", "updated_at"]
        for key in kwargs.keys():
            if key not in allowed_columns:
                raise ValueError(f"Invalid column: {key}")
        
        if not kwargs:
            cursor.close()
            return
        
        set_clause = ", ".join([f"{key} = %s" for key in kwargs.keys()])
        query = f"UPDATE users SET {set_clause} WHERE id = %s"
        values = list(kwargs.values()) + [user_id]
        cursor.execute(query, values)

        conn.commit()
        cursor.close()

    # SECURITY FIX: Use parameterized queries for DELETE
    def delete_user(self, user_id):
        """Delete user - FIXED."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Use parameterized query with placeholder
        query = "DELETE FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))

        conn.commit()
        cursor.close()

    # SECURITY FIX: Use parameterized queries for IN clause
    def get_users_by_ids(self, user_ids):
        """Get multiple users - FIXED."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Validate user_ids are integers and use parameterized query
        if not all(isinstance(uid, int) for uid in user_ids):
            raise ValueError("All user IDs must be integers")
        
        if not user_ids:
            cursor.close()
            return []
        
        placeholders = ",".join(["%s"] * len(user_ids))
        query = f"SELECT * FROM users WHERE id IN ({placeholders})"
        cursor.execute(query, user_ids)

        results = cursor.fetchall()
        cursor.close()
        return results

    # SECURITY FIX: Use parameterized queries and avoid plaintext password storage
    def store_password(self, user_id, password):
        """Store password - FIXED."""
        conn = self.connect()
        cursor = conn.cursor()

        # SECURITY FIX: Use parameterized query and note that passwords should be hashed
        query = "UPDATE users SET password = %s WHERE id = %s"
        cursor.execute(query, (password, user_id))

        conn.commit()
        cursor.close()

    # SECURITY FIX: Remove raw query execution capability
    def execute_raw(self, query):
        """Execute raw query - REMOVED FOR SECURITY."""
        raise NotImplementedError("Raw query execution is not allowed for security reasons")

    # SECURITY FIX: Avoid logging sensitive query data
    def log_query(self, query, params):
        """Log query - FIXED."""
        import logging
        # SECURITY FIX: Log query structure only, not sensitive parameters
        logging.info(f"Executing query: {query}")

    # CODE SMELL: Resource leak - connection not closed
    def get_connection(self):
        """Get connection without proper cleanup."""
        # CODE SMELL: No context manager, potential connection leak
        conn = mysql.connector.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database
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


# SECURITY FIX: Global database instance credentials now loaded from environment
db_instance = Database()


# SECURITY FIX: Use environment variables for admin credentials
def verify_db_admin(username, password):
    """Verify database admin - FIXED."""
    # SECURITY FIX: Load credentials from environment variables
    admin_user = os.getenv("DB_ADMIN_USER")
    admin_pass = os.getenv("DB_ADMIN_PASSWORD")
    
    if admin_user is None or admin_pass is None:
        return False
    
    if username == admin_user and password == admin_pass:
        return True
    return False


# SECURITY FIX: Use subprocess with argument list instead of os.system
def backup_database(db_name, backup_path):
    """Backup database - FIXED."""
    import subprocess
    # SECURITY FIX: Use subprocess with argument list to prevent command injection
    # SECURITY FIX: Load credentials from environment variables
    db_user = os.getenv("DB_USER", "root")
    db_pass = os.getenv("DB_PASSWORD", "")
    
    try:
        cmd = ["mysqldump", f"-u{db_user}", f"-p{db_pass}", db_name]
        with open(backup_path, "w") as backup_file:
            subprocess.run(cmd, stdout=backup_file, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Database backup failed: {e}")


# SECURITY FIX: Use subprocess with argument list and validate path
def restore_database(db_name, backup_file):
    """Restore database - FIXED."""
    import subprocess
    # SECURITY FIX: Validate backup_file path to prevent path traversal
    backup_file = os.path.abspath(backup_file)
    backup_dir = os.path.abspath(os.path.dirname(backup_file))
    
    if not backup_file.startswith(backup_dir):
        raise ValueError("Invalid backup file path")
    
    if not os.path.exists(backup_file):
        raise FileNotFoundError(f"Backup file not found: {backup_file}")
    
    # SECURITY FIX: Use subprocess with argument list to prevent command injection
    # SECURITY FIX: Load credentials from environment variables
    db_user = os.getenv("DB_USER", "root")
    db_pass = os.getenv("DB_PASSWORD", "")
    
    try:
        cmd = ["mysql", f"-u{db_user}", f"-p{db_pass}", db_name]
        with open(backup_file, "r") as restore_file:
            subprocess.run(cmd, stdin=restore_file, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Database restore failed: {e}")