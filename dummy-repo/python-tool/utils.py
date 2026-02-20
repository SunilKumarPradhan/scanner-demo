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
import secrets  # SECURITY FIX: use cryptographically secure random functions


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
    return yaml.safe_load(yaml_string)


# VULNERABILITY: Unsafe YAML loading
def load_yaml_file(filepath):
    """Load YAML file - VULNERABLE."""
    with open(filepath) as f:
        # VULNERABILITY: yaml.load without Loader specification
        return yaml.safe_load(f)  # SECURITY FIX: use safe_load


# VULNERABILITY: Weak hashing
def hash_data(data):
    """Hash data - VULNERABLE."""
    # VULNERABILITY: MD5 is cryptographically broken
    return hashlib.sha256(data.encode()).hexdigest()  # SECURITY FIX: use SHA-256


# VULNERABILITY: Weak hashing (SHA1)
def hash_password(password):
    """Hash password - VULNERABLE."""
    # VULNERABILITY: SHA1 is deprecated for security use
    return hashlib.sha256(password.encode()).hexdigest()  # SECURITY FIX: use SHA-256


# VULNERABILITY: Insecure random
def generate_password(length=12):
    """Generate password - VULNERABLE."""
    import string
    # VULNERABILITY: random module is not cryptographically secure
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))  # SECURITY FIX: use secrets


# VULNERABILITY: Insecure token generation
def generate_session_token():
    """Generate session token - VULNERABLE."""
    # VULNERABILITY: Predictable token generation
    return secrets.token_hex(16)  # SECURITY FIX: use cryptographically secure token


# VULNERABILITY: SSRF (Server-Side Request Forgery)
def fetch_url(url):
    """Fetch URL content - VULNERABLE."""
    # VULNERABILITY: No URL validation
    response = urllib.request.urlopen(url)
    return response.read()


# VULNERABILITY: SSL certificate verification disabled
def fetch_insecure(url):
    """Fetch URL without SSL verification - VULNERABLE."""
    # SECURITY FIX: Use default SSL context with verification enabled
    context = ssl.create_default_context()
    response = urllib.request.urlopen(url, context=context)
    return response.read()


# VULNERABILITY: Hardcoded credentials
def connect_to_server():
    """Connect to server - VULNERABLE."""
    # SECURITY FIX: Load credentials from environment variables
    HOST = os.getenv("SERVER_HOST", "127.0.0.1")
    USERNAME = os.getenv("SERVER_USER")
    PASSWORD = os.getenv("SERVER_PASS")
    API_KEY = os.getenv("SERVER_API_KEY")
    return {"host": HOST, "user": USERNAME, "pass": PASSWORD, "key": API_KEY}


# VULNERABILITY: Regex DoS
def validate_email(email):
    """Validate email - VULNERABLE."""
    # SECURITY FIX: Use efficient regex pattern
    pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    return bool(re.fullmatch(pattern, email))


# VULNERABILITY: Regex DoS
def validate_complex_string(s):
    """Validate string - VULNERABLE."""
    # SECURITY FIX: Simplify pattern to avoid catastrophic backtracking
    return bool(re.fullmatch(r'a+', s))


# VULNERABILITY: Log injection
def log_user_action(username, action):
    """Log user action - VULNERABLE."""
    import logging
    # VULNERABILITY: Unsanitized user input in logs
    logging.info(f"User {username} performed action: {action}")


# VULNERABILITY: Temporary file creation issues
def create_temp_file(data):
    """Create temp file - VULNERABLE."""
    # SECURITY FIX: Use secure temporary file creation
    with tempfile.NamedTemporaryFile(delete=False, mode='w', prefix='data_', suffix='.tmp') as tf:
        tf.write(data)
        return tf.name


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


# CODE SMELL: Function too long
def complex_business_logic(input_data):
    """Complex function - CODE SMELL."""
    result = {}

    # Name processing
    name = input_data.get('name')
    if name:
        result['name'] = name if name[0].isupper() else name.capitalize()
    else:
        result['name'] = 'Anonymous' if 'name' not in input_data else 'Unknown'

    # Age processing
    age = input_data.get('age')
    if isinstance(age, int) and 0 <= age <= 120:
        result['age'] = age
    else:
        result['age'] = 0 if isinstance(age, int) else None

    # Email processing
    email = input_data.get('email')
    if email and '@' in email and '.' in email:
        result['email'] = email
    else:
        result['email'] = None

    # Phone processing
    phone = input_data.get('phone')
    if phone:
        clean_phone = ''.join(c for c in phone if c.isdigit())
        result['phone'] = clean_phone if len(clean_phone) >= 10 else None
    else:
        result['phone'] = None

    return result


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


# CODE SMELL: Too many parameters
def create_record(**kwargs):
    """Create record - TOO MANY PARAMETERS."""
    return kwargs


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


# VULNERABILITY: Unsafe file permissions
def create_file_with_permissions(filepath, content):
    """Create file with permissions - VULNERABLE."""
    with open(filepath, 'w') as f:
        f.write(content)
    # VULNERABILITY: World-writable permissions
    os.chmod(filepath, 0o600)  # SECURITY FIX: restrict permissions


# VULNERABILITY: Binding to all interfaces
def start_server():
    """Start server - VULNERABLE."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # VULNERABILITY: Binding to 0.0.0.0
    sock.bind(('127.0.0.1', 8080))  # SECURITY FIX: bind to localhost
    sock.listen(5)
    return sock