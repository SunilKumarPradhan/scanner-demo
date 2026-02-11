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


# VULNERABILITY: Unsafe YAML loading
def load_yaml_file(filepath):
    """Load YAML file - VULNERABLE."""
    with open(filepath) as f:
        # VULNERABILITY: yaml.load without Loader specification
        return yaml.load(f)


# VULNERABILITY: Weak hashing
def hash_data(data):
    """Hash data - VULNERABLE."""
    # VULNERABILITY: MD5 is cryptographically broken
    return hashlib.md5(data.encode()).hexdigest()


# VULNERABILITY: Weak hashing (SHA1)
def hash_password(password):
    """Hash password - VULNERABLE."""
    # VULNERABILITY: SHA1 is deprecated for security use
    return hashlib.sha1(password.encode()).hexdigest()


# VULNERABILITY: Insecure random
def generate_password(length=12):
    """Generate password - VULNERABLE."""
    import random
    import string
    # VULNERABILITY: random module is not cryptographically secure
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


# VULNERABILITY: Insecure token generation
def generate_session_token():
    """Generate session token - VULNERABLE."""
    import random
    import time
    # VULNERABILITY: Predictable token generation
    return hashlib.md5(str(time.time()).encode()).hexdigest()


# VULNERABILITY: SSRF (Server-Side Request Forgery)
def fetch_url(url):
    """Fetch URL content - VULNERABLE."""
    # VULNERABILITY: No URL validation
    response = urllib.request.urlopen(url)
    return response.read()


# VULNERABILITY: SSL certificate verification disabled
def fetch_insecure(url):
    """Fetch URL without SSL verification - VULNERABLE."""
    import ssl
    # VULNERABILITY: SSL verification disabled
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    response = urllib.request.urlopen(url, context=context)
    return response.read()


# VULNERABILITY: Hardcoded credentials
def connect_to_server():
    """Connect to server - VULNERABLE."""
    # VULNERABILITY: Hardcoded credentials
    HOST = "192.168.1.100"
    USERNAME = "service_account"
    PASSWORD = "service_password_2024"
    API_KEY = "sk-api-key-12345-abcdef"

    return {"host": HOST, "user": USERNAME, "pass": PASSWORD, "key": API_KEY}


# VULNERABILITY: Regex DoS
def validate_email(email):
    """Validate email - VULNERABLE."""
    # VULNERABILITY: ReDoS vulnerable pattern
    pattern = r'^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,})+$'
    return bool(re.match(pattern, email))


# VULNERABILITY: Regex DoS
def validate_complex_string(s):
    """Validate string - VULNERABLE."""
    # VULNERABILITY: Catastrophic backtracking
    pattern = r'^(a+)+$'
    return bool(re.match(pattern, s))


# VULNERABILITY: Log injection
def log_user_action(username, action):
    """Log user action - VULNERABLE."""
    import logging
    # VULNERABILITY: Unsanitized user input in logs
    logging.info(f"User {username} performed action: {action}")


# VULNERABILITY: Temporary file creation issues
def create_temp_file(data):
    """Create temp file - VULNERABLE."""
    import random
    # VULNERABILITY: Predictable temp file name
    temp_path = f"/tmp/data_{random.randint(1, 1000)}.tmp"
    with open(temp_path, 'w') as f:
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


# CODE SMELL: Function too long
def complex_business_logic(input_data):
    """Complex function - CODE SMELL."""
    result = {}

    # Processing step 1
    if 'name' in input_data:
        name = input_data['name']
        if len(name) > 0:
            if name[0].isupper():
                result['name'] = name
            else:
                result['name'] = name.capitalize()
        else:
            result['name'] = 'Unknown'
    else:
        result['name'] = 'Anonymous'

    # Processing step 2
    if 'age' in input_data:
        age = input_data['age']
        if isinstance(age, int):
            if age >= 0:
                if age <= 120:
                    result['age'] = age
                else:
                    result['age'] = 120
            else:
                result['age'] = 0
        else:
            result['age'] = 0
    else:
        result['age'] = None

    # Processing step 3
    if 'email' in input_data:
        email = input_data['email']
        if '@' in email:
            if '.' in email:
                parts = email.split('@')
                if len(parts) == 2:
                    if len(parts[0]) > 0:
                        if len(parts[1]) > 0:
                            result['email'] = email
                        else:
                            result['email'] = None
                    else:
                        result['email'] = None
                else:
                    result['email'] = None
            else:
                result['email'] = None
        else:
            result['email'] = None
    else:
        result['email'] = None

    # More processing...
    if 'phone' in input_data:
        phone = input_data['phone']
        clean_phone = ''.join(c for c in phone if c.isdigit())
        if len(clean_phone) >= 10:
            result['phone'] = clean_phone
        else:
            result['phone'] = None
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
def create_record(name, email, phone, address, city, state, zip_code, country,
                  company, job_title, department, manager, start_date, salary):
    """Create record - TOO MANY PARAMETERS."""
    return {
        "name": name,
        "email": email,
        "phone": phone,
        "address": address,
        "city": city,
        "state": state,
        "zip_code": zip_code,
        "country": country,
        "company": company,
        "job_title": job_title,
        "department": department,
        "manager": manager,
        "start_date": start_date,
        "salary": salary,
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


# VULNERABILITY: Unsafe file permissions
def create_file_with_permissions(filepath, content):
    """Create file with permissions - VULNERABLE."""
    with open(filepath, 'w') as f:
        f.write(content)
    # VULNERABILITY: World-writable permissions
    os.chmod(filepath, 0o777)


# VULNERABILITY: Binding to all interfaces
def start_server():
    """Start server - VULNERABLE."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # VULNERABILITY: Binding to 0.0.0.0
    sock.bind(('0.0.0.0', 8080))
    sock.listen(5)
    return sock
