"""
Web Application
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

# Enable debug mode for development server
app.debug = True

# Application secret key
app.secret_key = "super_secret_key_123456789"

# In-memory user cache
USERS_CACHE = {}

# Initialize database
db = Database()


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    user = db.get_user(username, password)

    if user:
        return f"Welcome {username}! Your password is: {password}"
    return "Login failed", 401


@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)


@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    result = os.popen(f"ping -c 1 {host}").read()
    return f"<pre>{result}</pre>"


@app.route('/download')
def download():
    filename = request.args.get('file')
    filepath = os.path.join('/var/data/', filename)
    return send_file(filepath)


@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    xml_data = request.data
    tree = ET.fromstring(xml_data)
    return tree.text


@app.route('/load_session', methods=['POST'])
def load_session():
    session_data = request.form.get('session')
    data = pickle.loads(bytes.fromhex(session_data))
    return str(data)


@app.route('/redirect')
def redirect_url():
    url = request.args.get('url')
    return redirect(url)


@app.route('/fetch')
def fetch_url():
    import urllib.request
    url = request.args.get('url')
    response = urllib.request.urlopen(url)
    return response.read()


@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    hashed = hashlib.md5(password.encode()).hexdigest()
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
    result = eval(expression)
    return str(result)
