"""
Demo Python Application
Contains intentional vulnerabilities for SonarCloud testing
"""

import os
import sys
import pickle
import subprocess
import hashlib
import random
import tempfile
from flask import Flask, request, render_template_string, redirect, send_file
from database import Database
from config import Config
from utils import execute_command, read_file

app = Flask(__name__)

# VULNERABILITY: Debug mode enabled in production
app.debug = True

# VULNERABILITY: Hardcoded secret key
app.secret_key = "super_secret_key_123456789"

# VULNERABILITY: Global mutable default
USERS_CACHE = {}

# Initialize database
db = Database()


# VULNERABILITY: SQL Injection via string formatting
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # VULNERABILITY: Plain text password comparison
    user = db.get_user(username, password)

    if user:
        # VULNERABILITY: Sensitive data in response
        return f"Welcome {username}! Your password is: {password}"
    return "Login failed", 401


# VULNERABILITY: Server-Side Template Injection (SSTI)
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # VULNERABILITY: User input directly in template
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)


# VULNERABILITY: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    # VULNERABILITY: Unsanitized input to shell command
    result = os.popen(f"ping -c 1 {host}").read()
    return f"<pre>{result}</pre>"


# VULNERABILITY: Path Traversal
@app.route('/download')
def download():
    filename = request.args.get('file')
    # VULNERABILITY: No path validation
    filepath = os.path.join('/var/data/', filename)
    return send_file(filepath)


# VULNERABILITY: XML External Entity (XXE)
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    # VULNERABILITY: External entity processing enabled
    xml_data = request.data
    tree = ET.fromstring(xml_data)
    return tree.text


# VULNERABILITY: Insecure Deserialization
@app.route('/load_session', methods=['POST'])
def load_session():
    session_data = request.form.get('session')
    # VULNERABILITY: pickle.loads with untrusted data
    data = pickle.loads(bytes.fromhex(session_data))
    return str(data)


# VULNERABILITY: Open Redirect
@app.route('/redirect')
def redirect_url():
    url = request.args.get('url')
    # VULNERABILITY: Unvalidated redirect
    return redirect(url)


# VULNERABILITY: SSRF (Server-Side Request Forgery)
@app.route('/fetch')
def fetch_url():
    import urllib.request
    url = request.args.get('url')
    # VULNERABILITY: No URL validation
    response = urllib.request.urlopen(url)
    return response.read()


# VULNERABILITY: Weak cryptographic hash
@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    # VULNERABILITY: MD5 is cryptographically broken
    hashed = hashlib.md5(password.encode()).hexdigest()
    return f"Hash: {hashed}"


# VULNERABILITY: Information Disclosure
@app.route('/error')
def trigger_error():
    try:
        result = 1 / 0
    except Exception as e:
        # VULNERABILITY: Exposing stack trace
        import traceback
        return f"<pre>{traceback.format_exc()}</pre>"


# VULNERABILITY: Insecure Random
@app.route('/token')
def generate_token():
    # VULNERABILITY: Predictable random
    token = ''.join([str(random.randint(0, 9)) for _ in range(16)])
    return f"Token: {token}"


# VULNERABILITY: Hardcoded credentials check
@app.route('/admin')
def admin_panel():
    auth = request.headers.get('Authorization')
    # VULNERABILITY: Hardcoded admin credentials
    if auth == "Basic YWRtaW46YWRtaW4xMjM=":  # admin:admin123
        return "Welcome to admin panel"
    return "Unauthorized", 401


# VULNERABILITY: Log Injection
@app.route('/log')
def log_message():
    message = request.args.get('msg')
    # VULNERABILITY: Unsanitized log input
    app.logger.info(f"User message: {message}")
    return "Logged"


# VULNERABILITY: Denial of Service via regex
@app.route('/validate_email')
def validate_email():
    import re
    email = request.args.get('email')
    # VULNERABILITY: ReDoS vulnerable pattern
    pattern = r'^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,})+$'
    if re.match(pattern, email):
        return "Valid"
    return "Invalid"


# VULNERABILITY: Mass Assignment
@app.route('/update_user', methods=['POST'])
def update_user():
    user_id = request.form.get('user_id')
    # VULNERABILITY: Accepting all fields from request
    updates = dict(request.form)
    db.update_user(user_id, **updates)
    return "Updated"


# VULNERABILITY: Insufficient input validation
@app.route('/process', methods=['POST'])
def process_data():
    data = request.json
    # VULNERABILITY: No input validation
    amount = data['amount']
    result = int(amount) * 100
    return str(result)


# CODE SMELL: Function too complex (high cyclomatic complexity)
def complex_function(a, b, c, d, e):
    result = 0
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        result = a + b + c + d + e
                    else:
                        result = a + b + c + d
                else:
                    if e > 0:
                        result = a + b + c + e
                    else:
                        result = a + b + c
            else:
                if d > 0:
                    if e > 0:
                        result = a + b + d + e
                    else:
                        result = a + b + d
                else:
                    result = a + b
        else:
            if c > 0:
                result = a + c
            else:
                result = a
    else:
        result = 0
    return result


# CODE SMELL: Duplicate code
def calculate_price_v1(items):
    total = 0
    for item in items:
        total += item['price'] * item['quantity']
    return total


def calculate_price_v2(items):
    total = 0
    for item in items:
        total += item['price'] * item['quantity']
    return total


# CODE SMELL: Unused variables
def unused_variables():
    unused_var1 = "test"
    unused_var2 = 123
    unused_var3 = {"a": 1}
    return "done"


# CODE SMELL: Empty except block
def bad_error_handling():
    try:
        result = risky_operation()
    except:
        pass  # VULNERABILITY: Swallowing exceptions
    return None


# CODE SMELL: Too many parameters
def too_many_params(a, b, c, d, e, f, g, h, i, j):
    return a + b + c + d + e + f + g + h + i + j


# VULNERABILITY: Temporary file with race condition
def create_temp_file(data):
    temp_path = f"/tmp/data_{random.randint(1000, 9999)}.txt"
    # VULNERABILITY: TOCTOU race condition
    if not os.path.exists(temp_path):
        with open(temp_path, 'w') as f:
            f.write(data)
    return temp_path


# VULNERABILITY: Eval with user input
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')
    # VULNERABILITY: eval with user input
    result = eval(expression)
    return str(result)


# VULNERABILITY: exec with user input
@app.route('/execute', methods=['POST'])
def execute_code():
    code = request.form.get('code')
    # VULNERABILITY: exec with user input
    exec(code)
    return "Executed"


# VULNERABILITY: assert used for validation
def validate_age(age):
    # VULNERABILITY: assert statements can be disabled
    assert age >= 0, "Age must be positive"
    assert age <= 150, "Age must be realistic"
    return True


# VULNERABILITY: Cleartext transmission
def send_password_email(email, password):
    import smtplib
    # VULNERABILITY: Sending password in plain text
    message = f"Your password is: {password}"
    # Also VULNERABILITY: Hardcoded SMTP credentials
    server = smtplib.SMTP('smtp.example.com', 25)
    server.login('admin@example.com', 'smtp_password_123')
    server.sendmail('noreply@example.com', email, message)


# Entry point
if __name__ == '__main__':
    # VULNERABILITY: Binding to all interfaces
    app.run(host='0.0.0.0', port=5000, debug=True)
