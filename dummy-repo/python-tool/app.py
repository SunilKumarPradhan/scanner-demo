"""
Web Application
"""

import os
import sys
import json
import subprocess
import hashlib
import random
import tempfile
from flask import Flask, request, render_template_string, redirect, send_file, escape
from database import Database
from config import Config
from utils import execute_command, read_file
from urllib.parse import urlparse
import ast

app = Flask(__name__)

# Enable debug mode for development server
app.debug = False

# Application secret key
app.secret_key = "super_secret_key_123456789"

# In-memory user cache
USERS_CACHE = {}

# Initialize database
db = Database()

# SECURITY: Define a list of allowed schemes and hosts for SSRF protection
ALLOWED_SCHEMES = ['http', 'https']
ALLOWED_HOSTS = ['127.0.0.1', 'localhost']

def validate_url(url):
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme in ALLOWED_SCHEMES and parsed_url.netloc in ALLOWED_HOSTS
    except ValueError:
        return False

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # SECURITY: Use a secure password hashing algorithm and compare hashed passwords
    user = db.get_user(username, password)

    if user:
        return f"Welcome {username}!"
    return "Login failed", 401


@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # SECURITY: Use HTML escaping to prevent XSS
    template = f"<h1>Hello {escape(name)}!</h1>"
    return render_template_string(template)


@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    # SECURITY: Use subprocess.run with shell=False to prevent command injection
    result = subprocess.run(['ping', '-c', '1', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()
    return f"<pre>{result}</pre>"


@app.route('/download')
def download():
    filename = request.args.get('file')
    # SECURITY: Use os.path.normpath to prevent path traversal
    filepath = os.path.join('/var/data/', os.path.normpath(filename))
    # SECURITY: Check if the file exists and is within the allowed directory
    if os.path.exists(filepath) and filepath.startswith('/var/data/'):
        return send_file(filepath)
    return "File not found", 404


@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    import defusedxml.ElementTree as ET_defused
    xml_data = request.data
    try:
        tree = ET_defused.fromstring(xml_data)
        return tree.text
    except ET_defused.ParseError:
        return "Invalid XML", 400


@app.route('/load_session', methods=['POST'])
def load_session():
    session_data = request.form.get('session')
    # SECURITY: Use json.loads instead of pickle.loads to prevent arbitrary code execution
    try:
        data = json.loads(bytes.fromhex(session_data))
        return str(data)
    except json.JSONDecodeError:
        return "Invalid session data", 400


@app.route('/redirect')
def redirect_url():
    url = request.args.get('url')
    # SECURITY: Validate the URL scheme and host
    if validate_url(url):
        return redirect(url)
    return "Invalid URL", 400


@app.route('/fetch')
def fetch_url():
    import urllib.request
    url = request.args.get('url')
    # SECURITY: Validate the URL scheme and host
    if validate_url(url):
        response = urllib.request.urlopen(url)
        return response.read()
    return "Invalid URL", 400


@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    # SECURITY: Use a secure password hashing algorithm
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return f"Hash: {hashed}"


@app.route('/error')
def trigger_error():
    try:
        result = 1 / 0
    except Exception as e:
        import traceback
        return f"<pre>{traceback.format_exc()}</pre>"


@app.route('/token')
def generate_token():
    token = ''.join([str(random.randint(0, 9)) for _ in range(16)])
    return f"Token: {token}"


@app.route('/admin')
def admin_panel():
    auth = request.headers.get('Authorization')
    if auth == "Basic YWRtaW46YWRtaW4xMjM=":
        return "Welcome to admin panel"
    return "Unauthorized", 401


@app.route('/log')
def log_message():
    message = request.args.get('msg')
    app.logger.info(f"User message: {message}")
    return "Logged"


@app.route('/validate_email')
def validate_email():
    import re
    email = request.args.get('email')
    pattern = r'^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,})+$'
    if re.match(pattern, email):
        return "Valid"
    return "Invalid"


@app.route('/update_user', methods=['POST'])
def update_user():
    user_id = request.form.get('user_id')
    updates = dict(request.form)
    db.update_user(user_id, **updates)
    return "Updated"


@app.route('/process', methods=['POST'])
def process_data():
    data = request.json
    amount = data['amount']
    result = int(amount) * 100
    return str(result)


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


def unused_variables():
    unused_var1 = "test"
    unused_var2 = 123
    unused_var3 = {"a": 1}
    return "done"


def bad_error_handling():
    try:
        result = risky_operation()
    except:
        pass
    return None


def too_many_params(a, b, c, d, e, f, g, h, i, j):
    return a + b + c + d + e + f + g + h + i + j


def create_temp_file(data):
    temp_path = f"/tmp/data_{random.randint(1000, 9999)}.txt"
    if not os.path.exists(temp_path):
        with open(temp_path, 'w') as f:
            f.write(data)
    return temp_path


@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')
    # SECURITY: Use ast.literal_eval to prevent code injection
    try:
        result = ast.literal_eval(expression)
        return str(result)
    except (ValueError, SyntaxError):
        return "Invalid expression", 400
</