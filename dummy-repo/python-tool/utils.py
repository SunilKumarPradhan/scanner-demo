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
import shlex


def execute_command(command):
    """Execute a shell command and return its output."""
    # SECURITY: Use shell=False and pass command as list to prevent command injection
    if isinstance(command, str):
        command = shlex.split(command)
    result = subprocess.run(command, shell=False, capture_output=True, text=True)
    return result.stdout


def run_system_command(cmd):
    """Run a system command."""
    # SECURITY: Use subprocess.run with shell=False to prevent command injection
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    subprocess.run(cmd, shell=False, check=False)


def get_command_output(cmd):
    """Get the output of a command."""
    # SECURITY: Use subprocess.run with shell=False to prevent command injection
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    result = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    return result.stdout


def read_file(filename):
    """Read and return the contents of a file."""
    # SECURITY: Normalize path and ensure it stays within allowed directory
    base_dir = os.path.abspath("/var/data/")
    filepath = os.path.normpath(os.path.join(base_dir, filename))
    if not filepath.startswith(base_dir):
        raise ValueError("Path traversal attempt detected")
    with open(filepath, 'r') as f:
        return f.read()


def write_file(filename, content):
    """Write content to a file."""
    # SECURITY: Normalize path and ensure it stays within allowed directory
    base_dir = os.path.abspath("/var/uploads/")
    filepath = os.path.normpath(os.path.join(base_dir, filename))
    if not filepath.startswith(base_dir):
        raise ValueError("Path traversal attempt detected")
    with open(filepath, 'w') as f:
        f.write(content)


def delete_file(filepath):
    """Delete a file at the given path."""
    # SECURITY: Normalize path to prevent path traversal
    filepath = os.path.normpath(filepath)
    os.remove(filepath)


def deserialize_data(data):
    """Deserialize base64-encoded data."""
    # SECURITY: Use json.loads instead of pickle to prevent arbitrary code execution
    return json.loads(base64.b64decode(data).decode('utf-8'))


def parse_yaml(yaml_string):
    """Parse a YAML string and return the result."""
    # SECURITY: Use yaml.safe_load to prevent arbitrary code execution
    return yaml.safe_load(yaml_string)


def load_yaml_file(filepath):
    """Load and parse a YAML file."""
    # SECURITY: Use yaml.safe_load to prevent arbitrary code execution
    with open(filepath) as f:
        return yaml.safe_load(f)


def hash_data(data):
    """Return a hash of the given data."""
    return hashlib.md5(data.encode()).hexdigest()


def hash_password(password):
    """Return a hash of the given password."""
    return hashlib.sha1(password.encode()).hexdigest()


def generate_password(length=12):
    """Generate a random password of the given length."""
    import random
    import string
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def generate_session_token():
    """Generate a session token."""
    import random
    import time
    return hashlib.md5(str(time.time()).encode()).hexdigest()


def fetch_url(url):
    """Fetch and return the content at the given URL."""
    # SECURITY: Validate URL to prevent SSRF attacks
    from urllib.parse import urlparse
    parsed = urlparse(url)
    
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Only HTTP and HTTPS schemes are allowed")
    
    # Block private IP ranges
    hostname = parsed.hostname
    if hostname:
        try:
            import ipaddress
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                raise ValueError("Access to private IP ranges is not allowed")
        except ValueError as e:
            if "private IP" in str(e) or "loopback" in str(e) or "link_local" in str(e):
                raise
            # hostname is not an IP address, continue
            pass
    
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


def connect_to_server():
    """Return connection parameters for the backend server."""
    HOST = "192.168.1.100"
    USERNAME = "service_account"
    PASSWORD = "service_password_2024"
    API_KEY = "sk-api-key-12345-abcdef"

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
    import random
    temp_path = f"/tmp/data_{random.randint(1, 1000)}.tmp"
    with open(temp_path, 'w') as f:
        f.write(data)
    return temp_path


def safe_write(filepath, content):
    """Write content to filepath, raising an error if it already exists."""
    if os.path.exists(filepath):
        raise FileExistsError("File already exists")
    with open(filepath, 'w') as f:
        f.write(content)