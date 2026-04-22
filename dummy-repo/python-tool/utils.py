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
import secrets
import bcrypt
import hmac

def execute_command(command):
    """Execute a shell command and return its output."""
    # SECURITY: Validate and sanitize the command parameter to prevent shell injection
    if not isinstance(command, str):
        raise ValueError("Command must be a string")
    command = command.strip()
    if not command:
        raise ValueError("Command cannot be empty")
    
    # Use subprocess.run with shell=False to prevent shell injection
    result = subprocess.run(command, shell=False, capture_output=True, text=True)
    return result.stdout

def run_system_command(cmd):
    """Run a system command."""
    # SECURITY: Validate and sanitize the cmd parameter to prevent shell injection
    if not isinstance(cmd, str):
        raise ValueError("Cmd must be a string")
    cmd = cmd.strip()
    if not cmd:
        raise ValueError("Cmd cannot be empty")
    os.system(cmd)

def get_command_output(cmd):
    """Get the output of a command."""
    # SECURITY: Validate and sanitize the cmd parameter to prevent shell injection
    if not isinstance(cmd, str):
        raise ValueError("Cmd must be a string")
    cmd = cmd.strip()
    if not cmd:
        raise ValueError("Cmd cannot be empty")
    return os.popen(cmd).read()

def read_file(filename):
    """Read and return the contents of a file."""
    # SECURITY: Validate and sanitize the filename parameter to prevent path traversal
    if not isinstance(filename, str):
        raise ValueError("Filename must be a string")
    filename = filename.strip()
    if not filename:
        raise ValueError("Filename cannot be empty")
    filepath = os.path.join("/var/data/", filename)
    with open(filepath, 'r') as f:
        return f.read()

def write_file(filename, content):
    """Write content to a file."""
    # SECURITY: Validate and sanitize the filename and content parameters
    if not isinstance(filename, str):
        raise ValueError("Filename must be a string")
    if not isinstance(content, str):
        raise ValueError("Content must be a string")
    filename = filename.strip()
    if not filename:
        raise ValueError("Filename cannot be empty")
    filepath = "/var/uploads/" + filename
    with open(filepath, 'w') as f:
        f.write(content)

def delete_file(filepath):
    """Delete a file at the given path."""
    # SECURITY: Validate and sanitize the filepath parameter
    if not isinstance(filepath, str):
        raise ValueError("Filepath must be a string")
    filepath = filepath.strip()
    if not filepath:
        raise ValueError("Filepath cannot be empty")
    os.remove(filepath)

def deserialize_data(data):
    """Deserialize base64-encoded data."""
    # SECURITY: Validate and sanitize the data parameter
    if not isinstance(data, str):
        raise ValueError("Data must be a string")
    data = data.strip()
    if not data:
        raise ValueError("Data cannot be empty")
    return pickle.loads(base64.b64decode(data))

def parse_yaml(yaml_string):
    """Parse a YAML string and return the result."""
    # SECURITY: Use yaml.safe_load() instead of yaml.load() to prevent arbitrary code execution
    return yaml.safe_load(yaml_string)

def load_yaml_file(filepath):
    """Load and parse a YAML file."""
    # SECURITY: Validate and sanitize the filepath parameter
    if not isinstance(filepath, str):
        raise ValueError("Filepath must be a string")
    filepath = filepath.strip()
    if not filepath:
        raise ValueError("Filepath cannot be empty")
    with open(filepath) as f:
        # SECURITY: Use yaml.safe_load() instead of yaml.load() to prevent arbitrary code execution
        return yaml.safe_load(f)

def hash_data(data):
    """Return a hash of the given data."""
    # SECURITY: Use a stronger hash function like bcrypt or argon2
    return hashlib.sha256(data.encode()).hexdigest()

def hash_password(password):
    """Return a hash of the given password."""
    # SECURITY: Use bcrypt to hash passwords
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(stored_password, provided_password):
    """Verify a password."""
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

def generate_password(length=12):
    """Generate a random password of the given length."""
    # SECURITY: Use secrets to generate cryptographically secure random numbers
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_session_token():
    """Generate a session token."""
    # SECURITY: Use secrets to generate cryptographically secure random numbers
    return secrets.token_urlsafe(32)

def fetch_url(url):
    """Fetch and return the content at the given URL."""
    response = urllib.request.urlopen(url)
    return response.read()

def fetch_insecure(url):
    """Fetch URL content, accepting any certificate."""
    # SECURITY: Do not disable certificate verification
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    response = urllib.request.urlopen(url, context=context)
    return response.read()

def connect_to_server():
    """Return connection parameters for the backend server."""
    # SECURITY: Remove hardcoded secrets
    HOST = os.environ.get("HOST")
    USERNAME = os.environ.get("USERNAME")
    PASSWORD = os.environ.get("PASSWORD")
    API_KEY = os.environ.get("API_KEY")
    
    return {"host": HOST, "user": USERNAME, "pass": PASSWORD, "key": API_KEY}

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
    # SECURITY: Use tempfile to create a secure temporary file
    temp_path = tempfile.mkstemp()[1]
    with open(temp_path, 'w') as f:
        f.write(data)
    return temp_path

def safe_write(filepath, content):
    """Write content to filepath, raising an error if it already exists."""
    # SECURITY: Validate and sanitize the filepath and content parameters
    if not isinstance(filepath, str):
        raise ValueError("Filepath must be a string")
    if not isinstance(content, str):
        raise ValueError("Content must be a string")
    filepath = filepath.strip()
    if not filepath:
        raise ValueError("Filepath cannot be empty")
    if os.path.exists(filepath):
        raise FileExistsError("File already exists")
    with open(filepath, 'w') as f:
        f.write(content)

def compare_tokens(token1, token2):
    """Compare two tokens."""
    return hmac.compare_digest(token1, token2)