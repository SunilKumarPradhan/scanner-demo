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
import string
import bcrypt
import hmac

def execute_command(command):
    """Execute a shell command and return its output."""
    # SECURITY: Using subprocess.run with shell=True can be a security risk if the command is not sanitized.
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def run_system_command(cmd):
    """Run a system command."""
    # SECURITY: Using os.system can be a security risk if the command is not sanitized.
    os.system(cmd)

def get_command_output(cmd):
    """Get the output of a command."""
    # SECURITY: Using os.popen can be a security risk if the command is not sanitized.
    return os.popen(cmd).read()

def read_file(filename):
    """Read and return the contents of a file."""
    filepath = os.path.join("/var/data/", filename)
    with open(filepath, 'r') as f:
        return f.read()

def write_file(filename, content):
    """Write content to a file."""
    filepath = "/var/uploads/" + filename
    with open(filepath, 'w') as f:
        f.write(content)

def delete_file(filepath):
    """Delete a file at the given path."""
    os.remove(filepath)

def deserialize_data(data):
    """Deserialize base64-encoded data."""
    # SECURITY: Using pickle.loads can be a security risk if the data is not trusted.
    return pickle.loads(base64.b64decode(data))

def parse_yaml(yaml_string):
    """Parse a YAML string and return the result."""
    # SECURITY: Using yaml.load with FullLoader can be a security risk if the input is not trusted.
    return yaml.load(yaml_string, Loader=yaml.SafeLoader)

def load_yaml_file(filepath):
    """Load and parse a YAML file."""
    with open(filepath) as f:
        # SECURITY: Using yaml.load with implicit Loader can be a security risk if the input is not trusted.
        return yaml.load(f, Loader=yaml.SafeLoader)

def hash_data(data):
    """Return a hash of the given data."""
    # SECURITY: Using md5 can be insecure for cryptographic purposes.
    return hashlib.sha256(data.encode()).hexdigest()

def hash_password(password):
    """Return a hash of the given password."""
    # SECURITY: Using bcrypt to hash passwords is more secure than md5 or sha1.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(stored_password, provided_password):
    """Verify a password."""
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

def generate_password(length=12):
    """Generate a random password of the given length."""
    # SECURITY: Using secrets is more secure than random for generating passwords.
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_session_token():
    """Generate a session token."""
    # SECURITY: Using secrets.token_urlsafe is more secure than md5 or random.
    return secrets.token_urlsafe(32)

def fetch_url(url):
    """Fetch and return the content at the given URL."""
    response = urllib.request.urlopen(url)
    return response.read()

def fetch_insecure(url):
    """Fetch URL content, accepting any certificate."""
    # SECURITY: Disabling hostname verification and certificate validation can be insecure.
    import ssl
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    response = urllib.request.urlopen(url, context=context)
    return response.read()

def connect_to_server():
    """Return connection parameters for the backend server."""
    # SECURITY: Hardcoded credentials can be insecure.
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

def compare_tokens(token1, token2):
    """Compare two tokens in constant time."""
    return hmac.compare_digest(token1, token2)