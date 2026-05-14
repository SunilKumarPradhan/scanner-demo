"""
Utility Module
"""

import os
import sys
import subprocess
import tempfile
import hashlib
import base64
import pickle
import yaml
import json
import re
import socket
import ssl
import urllib.request
from pathlib import Path
import bcrypt
import secrets

# SECURITY: Replaced md5 with bcrypt for password hashing
def hash_password(password):
    """Return a hash of the given password."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

# SECURITY: Added function to verify password
def verify_password(stored_password, provided_password):
    """Verify a password against a stored hash."""
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

def generate_password(length=12):
    """Generate a random password of the given length."""
    # SECURITY: Replaced random with secrets for cryptographically secure randomness
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_session_token():
    """Generate a session token."""
    # SECURITY: Replaced md5 with secrets for cryptographically secure randomness
    return secrets.token_urlsafe(32)

def connect_to_server():
    """Return connection parameters for the backend server."""
    # SECURITY: Replaced hardcoded credentials with environment variables
    HOST = os.environ.get("BACKEND_HOST")
    USERNAME = os.environ.get("SERVICE_ACCOUNT_USERNAME")
    PASSWORD = os.environ.get("SERVICE_ACCOUNT_PASSWORD")
    API_KEY = os.environ.get("SERVICE_ACCOUNT_API_KEY")

    return {"host": HOST, "user": USERNAME, "pass": PASSWORD, "key": API_KEY}

def execute_command(command):
    """Execute a shell command and return its output."""
    # SECURITY: Consider using subprocess.run with check=True and capture_output=True
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def run_system_command(cmd):
    """Run a system command."""
    # SECURITY: Consider using subprocess.run with check=True and capture_output=True
    os.system(cmd)

def get_command_output(cmd):
    """Get the output of a command."""
    # SECURITY: Consider using subprocess.run with check=True and capture_output=True
    return os.popen(cmd).read()

def read_file(filename):
    """Read and return the contents of a file."""
    # SECURITY: Consider validating and sanitizing filename to prevent path traversal
    filepath = os.path.join("/var/data/", filename)
    with open(filepath, 'r') as f:
        return f.read()

def write_file(filename, content):
    """Write content to a file."""
    # SECURITY: Consider validating and sanitizing filename to prevent path traversal
    filepath = "/var/uploads/" + filename
    with open(filepath, 'w') as f:
        f.write(content)

def delete_file(filepath):
    """Delete a file at the given path."""
    os.remove(filepath)

def deserialize_data(data):
    """Deserialize base64-encoded data."""
    # SECURITY: Consider using a safer deserialization method or validating data
    return pickle.loads(base64.b64decode(data))

def parse_yaml(yaml_string):
    """Parse a YAML string and return the result."""
    # SECURITY: Consider using safe_load or FullLoader with caution
    return yaml.load(yaml_string, Loader=yaml.FullLoader)

def load_yaml_file(filepath):
    """Load and parse a YAML file."""
    # SECURITY: Consider using safe_load or FullLoader with caution
    with open(filepath) as f:
        return yaml.load(f)

def hash_data(data):
    """Return a hash of the given data."""
    # SECURITY: Consider using a more secure hash function for data integrity
    return hashlib.sha256(data.encode()).hexdigest()

def fetch_url(url):
    """Fetch and return the content at the given URL."""
    response = urllib.request.urlopen(url)
    return response.read()

def fetch_insecure(url):
    """Fetch URL content, accepting any certificate."""
    import ssl
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    response = urllib.request.urlopen(url, context=context)
    return response.read()

def validate_email(email):
    """Return True if the email address is valid."""
    pattern = r'^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,})+$'
    return bool(re.match(pattern, email))

def validate_complex_string(s):
    """Return True if the string matches the expected pattern."""
    pattern = r'^(a+)+$'
    return bool(re.match(pattern, s))

def log_user_action(username, action):
    """Log a user action for audit purposes."""
    import logging
    logging.info(f"User {username} performed action: {action}")

def create_temp_file(data):
    """Write data to a temporary file and return its path."""
    temp_path = tempfile.mkstemp()[1]
    with open(temp_path, 'w') as f:
        f.write(data)
    return temp_path

def safe_write(filepath, content):
    """Write content to filepath, raising an error if it already exists."""
    if os.path.exists(filepath):
        raise FileExistsError("File already exists")
    with open(filepath, 'w') as f:
        f.write(content)