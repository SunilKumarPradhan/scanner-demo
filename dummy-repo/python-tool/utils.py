"""
Utility Module
Contains intentional security vulnerabilities for SonarCloud testing
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


# VULNERABILITY: Command Injection
def execute_command(command):
    """Execute shell command - VULNERABLE."""
    # VULNERABILITY: shell=True with user input
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


# VULNERABILITY: Command Injection via os.system
def run_system_command(cmd):
    """Run system command - VULNERABLE."""
    # VULNERABILITY: os.system with user input
    os.system(cmd)


# VULNERABILITY: Command Injection via os.popen
def get_command_output(cmd):
    """Get command output - VULNERABLE."""
    # VULNERABILITY: os.popen with user input
    return os.popen(cmd).read()


# VULNERABILITY: Path Traversal
def read_file(filename):
    """Read file contents - VULNERABLE."""
    # VULNERABILITY: No path validation
    filepath = os.path.join("/var/data/", filename)
    with open(filepath, 'r') as f:
        return f.read()


# VULNERABILITY: Path Traversal
def write_file(filename, content):
    """Write file - VULNERABLE."""
    # VULNERABILITY: No path sanitization
    filepath = "/var/uploads/" + filename
    with open(filepath, 'w') as f:
        f.write(content)


# VULNERABILITY: Arbitrary file deletion
def delete_file(filepath):
    """Delete file - VULNERABLE."""
    # VULNERABILITY: No validation
    os.remove(filepath)


# VULNERABILITY: Insecure deserialization (pickle)
def deserialize_data(data):
    """Deserialize data - VULNERABLE."""
    # VULNERABILITY: pickle.loads with untrusted data
    return pickle.loads(base64.b64decode(data))


# VULNERABILITY: Insecure deserialization (YAML)
def parse_yaml(yaml_string):
    """Parse YAML - VULNERABLE."""
    # VULNERABILITY: yaml.load without safe_load
    return yaml.load(yaml_string, Loader=yaml.FullLoader)


# SECURITY FIX: Use safe_load with proper Loader
def load_yaml_file(filepath):
    """Load YAML file - VULNERABLE."""
    with open(filepath) as f:
        return yaml.safe_load(f)


# SECURITY FIX: Use SHA-256 instead of MD5
def hash_data(data):
    """Hash data - VULNERABLE."""
    return hashlib.sha256(data.encode()).hexdigest()


# SECURITY FIX: Use SHA-256 instead of SHA1
def hash_password(password):
    """Hash password - VULNERABLE."""
    return hashlib.sha256(password.encode()).hexdigest()


# SECURITY FIX: Use secrets module for cryptographically secure random
def generate_password(length=12):
    """Generate password - VULNERABLE."""
    import secrets
    import string
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))


# SECURITY FIX: Use secrets module for token generation
def generate_session_token():
    """Generate session token - VULNERABLE."""
    import secrets
    return secrets.token_hex(32)


# VULNERABILITY: SSRF (Server-Side Request Forgery)
def fetch_url(url):
    """Fetch URL content - VULNERABLE."""
    # VULNERABILITY: No URL validation
    response = urllib.request.urlopen(url)
    return response.read()


# SECURITY FIX: Enable SSL verification
def fetch_insecure(url):
    """Fetch URL without SSL verification - VULNERABLE."""
    import ssl
    context = ssl.create_default_context()

    response = urllib.request.urlopen(url, context=context)
    return response.read()


# SECURITY FIX: Load credentials from environment variables
def connect_to_server():
    """Connect to server - VULNERABLE."""
    HOST = os.environ.get("SERVER_HOST", "localhost")
    USERNAME = os.environ.get("SERVICE_USERNAME", "")
    PASSWORD = os.environ.get("SERVICE_PASSWORD", "")
    API_KEY = os.environ.get("SERVICE_API_KEY", "")

    return {"host": HOST, "user": USERNAME, "pass": PASSWORD, "key": API_KEY}


# SECURITY FIX: Use simpler regex pattern to avoid ReDoS
def validate_email(email):
    """Validate email - VULNERABLE."""
    pattern = r'^[a-zA-Z0-9_.\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9]{2,}$'
    return bool(re.match(pattern, email))


# SECURITY FIX: Use simpler regex pattern to avoid catastrophic backtracking
def validate_complex_string(s):
    """Validate string - VULNERABLE."""
    pattern = r'^a+$'
    return bool(re.match(pattern, s))


# VULNERABILITY: Log injection
def log_user_action(username, action):
    """Log user action - VULNERABLE."""
    import logging
    # VULNERABILITY: Unsanitized user input in logs
    logging.info(f"User {username} performed action: {action}")


# SECURITY FIX: Use tempfile module for secure temp file creation
def create_temp_file(data):
    """Create temp file - VULNERABLE."""
    fd, temp_path = tempfile.mkstemp(suffix='.tmp', prefix='data_')
    with os.fdopen(fd, 'w') as f:
        f.write(data)
    return temp_path


# VULNERABILITY: Race condition (TOCTOU)
def safe_write(filepath, content):
    """Safe write - NOT ACTUALLY SAFE (TOCTOU)."""
    # VULNERABILITY: Time-of-check to time-of-use
    if os.path.exists(filepath):
        raise FileExistsError("File already exists")
    # Race condition window here
    with open(filepath, 'w') as f:
        f.write(content)


# VULNERABILITY: Eval usage
def calculate_expression(expr):
    """Calculate expression - VULNERABLE."""
    # VULNERABILITY: eval with user input
    return eval(expr)


# VULNERABILITY: Exec usage
def run_code(code_string):
    """Run code - VULNERABLE."""
    # VULNERABILITY: exec with user input
    exec(code_string)


# VULNERABILITY: Compile and exec
def execute_dynamic_code(code):
    """Execute dynamic code - VULNERABLE."""
    # VULNERABILITY: compile and exec with user input
    compiled = compile(code, '<string>', 'exec')
    exec(compiled)


# VULNERABILITY: Assert used for validation
def validate_input(value, min_val, max_val):
    """Validate input - VULNERABLE."""
    # VULNERABILITY: assert can be disabled with -O flag
    assert isinstance(value, (int, float)), "Value must be numeric"
    assert value >= min_val, f"Value must be >= {min_val}"
    assert value <= max_val, f"Value must be <= {max_val}"
    return True


# VULNERABILITY: Information disclosure
def get_system_info():
    """Get system info - VULNERABLE."""
    # VULNERABILITY: Exposing system information
    return {
        "python_version": sys.version,
        "platform": sys.platform,
        "path": sys.path,
        "env": dict(os.environ),  # VULNERABILITY: Exposing environment
        "cwd": os.getcwd(),
    }


# VULNERABILITY: Weak comparison
def check_password(provided, stored):
    """Check password - VULNERABLE."""
    # VULNERABILITY: Non-constant time comparison (timing attack)
    if provided == stored:
        return True
    return False


# VULNERABILITY: Dangerous default
def process_data(data, processor=lambda x: eval(x)):
    """Process data - VULNERABLE."""
    # VULNERABILITY: Dangerous default argument
    return processor(data)


# SECURITY FIX: Reduce cognitive complexity by extracting helper functions
def _process_name(input_data):
    """Helper to process name field."""
    if 'name' not in input_data:
        return 'Anonymous'
    name = input_data['name']
    if len(name) == 0:
        return 'Unknown'
    return name if name[0].isupper() else name.capitalize()


def _process_age(input_data):
    """Helper to process age field."""
    if 'age' not in input_data:
        return None
    age = input_data['age']
    if not isinstance(age, int):
        return 0
    if age < 0:
        return 0
    if age > 120:
        return 120
    return age


def _process_email(input_data):
    """Helper to process email field."""
    if 'email' not in input_data:
        return None
    email = input_data['email']
    if '@' not in email or '.' not in email:
        return None
    parts = email.split('@')
    if len(parts) != 2 or len(parts[0]) == 0 or len(parts[1]) == 0:
        return None
    return email


def _process_phone(input_data):
    """Helper to process phone field."""
    if 'phone' not in input_data:
        return None
    phone = input_data['phone']
    clean_phone = ''.join(c for c in phone if c.isdigit())
    return clean_phone if len(clean_phone) >= 10 else None


def complex_business_logic(input_data):
    """Complex function - CODE SMELL."""
    return {
        'name': _process_name(input_data),
        'age': _process_age(input_data),
        'email': _process_email(input_data),
        'phone': _process_phone(input_data),
    }


# CODE SMELL: Duplicated code
def format_user_v1(user):
    """Format user v1."""
    return f"{user['first_name']} {user['last_name']} ({user['email']})"


def format_user_v2(user):
    """Format user v2 - DUPLICATE."""
    return f"{user['first_name']} {user['last_name']} ({user['email']})"


# CODE SMELL: Dead code
def unused_function():
    """This function is never called."""
    pass


def another_unused_function():
    """This function is also never called."""
    x = 1
    y = 2
    z = x + y
    return z


# SECURITY FIX: Use a data class or dictionary to reduce parameter count
def create_record(record_data):
    """Create record - TOO MANY PARAMETERS."""
    return {
        "name": record_data.get("name"),
        "email": record_data.get("email"),
        "phone": record_data.get("phone"),
        "address": record_data.get("address"),
        "city": record_data.get("city"),
        "state": record_data.get("state"),
        "zip_code": record_data.get("zip_code"),
        "country": record_data.get("country"),
        "company": record_data.get("company"),
        "job_title": record_data.get("job_title"),
        "department": record_data.get("department"),
        "manager": record_data.get("manager"),
        "start_date": record_data.get("start_date"),
        "salary": record_data.get("salary"),
    }


# CODE SMELL: Magic numbers
def calculate_shipping(weight, distance):
    """Calculate shipping - MAGIC NUMBERS."""
    # CODE SMELL: Unexplained numeric constants
    base_cost = 5.99
    weight_factor = 0.15
    distance_factor = 0.02

    if weight > 50:
        weight = weight * 1.25  # What is 1.25?

    if distance > 1000:
        distance = distance * 0.85  # What is 0.85?

    return base_cost + (weight * weight_factor) + (distance * distance_factor)


# SECURITY FIX: Use restrictive file permissions
def create_file_with_permissions(filepath, content):
    """Create file with permissions - VULNERABLE."""
    with open(filepath, 'w') as f:
        f.write(content)
    os.chmod(filepath, 0o644)


# VULNERABILITY: Binding to all interfaces
def start_server():
    """Start server - VULNERABLE."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # VULNERABILITY: Binding to 0.0.0.0
    sock.bind(('0.0.0.0', 8080))
    sock.listen(5)
    return sock