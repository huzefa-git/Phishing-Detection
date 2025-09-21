from flask import Flask, render_template, request, jsonify, session, flash, redirect, url_for, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
import pickle
import pandas as pd
import numpy as np
from feature_extraction import extract_features
import whois
from datetime import datetime
import ssl
import socket
from urllib.parse import urlparse
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure DB and uploads
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = 'Uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'html', 'csv'}

db = SQLAlchemy(app)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash("Please log in first!", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Load trained model
model_path = 'phishing_model.pkl'
with open(model_path, 'rb') as file:
    phishing_model = pickle.load(file)

# Helpers
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def predict_url(url):
    features = extract_features(url)
    df = pd.DataFrame([features])
    prediction = phishing_model.predict(df)[0]
    return prediction

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'username' in session:
        flash("You are already logged in", "info")
        return redirect(url_for('menu'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm-password']

        if password != confirm:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "warning")
            return redirect(url_for('signup'))

        new_user = User(username=username, email=email, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('menu'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for('menu'))
        flash("Invalid credentials", "danger")

    return render_template('login.html')

@app.route('/menu')
@login_required
def menu():
    return render_template('menu.html', username=session['username'])

@app.route('/check', methods=['GET', 'POST'])
@login_required
def file_check():
    if request.method == 'GET':
        return render_template('check_url.html')

    url = request.form.get('url')
    file = request.files.get('file')
    results = []

    if url:
        try:
            prediction = predict_url(url)
            result = "Phishing Detected ⚠️" if prediction == 0 else "Looks Safe ✅"
        except Exception as e:
            result = f"Error: {str(e)}"
        results.append(f"{result}")

    elif file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                urls = f.readlines()

            for u in urls:
                u = u.strip()
                if not u:
                    continue
                try:
                    prediction = predict_url(u)
                    result = "Phishing Detected ⚠️" if prediction == 0 else "Looks Safe ✅"
                except Exception as e:
                    result = f"Error: {str(e)}"
                results.append(f"{u}: {result}")
        except Exception as e:
            results.append(f"Error processing file: {str(e)}")
        finally:
            os.remove(file_path)
    else:
        results.append("No URL or valid file provided ❌")

    return jsonify({'result': '\n'.join(results)})

@app.route('/analyze_headers', methods=['GET', 'POST'])
@login_required
def analyze_email_headers():
    if request.method == 'GET':
        return render_template('analyze_email_headers.html', result=None)

    headers = request.form.get('email-headers', '').strip()
    result = {}

    if not headers:
        result['message'] = "Please provide email headers."
    else:
        try:
            result['message'] = analyze_headers(headers)
        except Exception as e:
            result['message'] = f"Error analyzing headers: {str(e)}"

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return Response(result['message'], mimetype='text/plain')
    else:
        return render_template('analyze_email_headers.html', result=result)

def analyze_headers(headers):
    if not headers.strip():
        return "No headers provided."

    lines = headers.strip().split('\n')
    analysis = []
    from_domain = None
    received_domains = []

    def extract_domain(email):
        match = re.search(r'@([\w.-]+)', email, re.IGNORECASE)
        return match.group(1).lower() if match else None

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith('Received:'):
            match = re.search(r'from\s+([\w.-]+)|from\s+\[(\d+\.\d+\.\d+\.\d+)\]', line, re.IGNORECASE)
            domain_or_ip = match.group(1) or match.group(2) or 'Unknown'
            value = line.replace('Received:', '', 1).strip()
            analysis.append(f"[+] Received: {value}")
            received_domains.append(domain_or_ip.lower())
        elif line.startswith('From:'):
            from_domain = extract_domain(line)
            value = line.replace('From:', '', 1).strip()
            analysis.append(f"[+] From: {value or 'No sender specified'}")
        elif line.startswith('Subject:'):
            value = line.replace('Subject:', '', 1).strip()
            analysis.append(f"[+] Subject: {value or 'No subject'}")
        elif line.startswith('Date:'):
            value = line.replace('Date:', '', 1).strip()
            analysis.append(f"[+] Date: {value or 'No date'}")
        elif line.startswith('Message-ID:'):
            value = line.replace('Message-ID:', '', 1).strip()
            analysis.append(f"[+] Message-ID: {value or 'Not provided'}")
        elif line.startswith(('Authentication-Results:', 'Received-SPF:')):
            value = line.replace('Authentication-Results:', '', 1).replace('Received-SPF:', '', 1).strip()
            analysis.append(f"[+] SPF: {value or 'Not provided'}")
        elif line.startswith('DKIM-Signature:'):
            value = line.replace('DKIM-Signature:', '', 1).strip()
            analysis.append(f"[+] DKIM: {value or 'Not provided'}")
        elif line.startswith('Return-Path:'):
            value = line.replace('Return-Path:', '', 1).strip()
            analysis.append(f"[+] Return-Path: {value or 'Not provided'}")

    if not analysis:
        return "No significant headers found for analysis."

    if from_domain and received_domains:
        if not any(from_domain == domain or f".{from_domain}" in domain for domain in received_domains if domain != 'unknown'):
            analysis.append("[!] Warning: Potential phishing - From domain does not match Received domains.")
    elif not from_domain and received_domains:
        analysis.append("[!] Warning: No valid From domain found - potential phishing risk.")
    elif not received_domains:
        analysis.append("[!] Warning: No Received headers found - potential phishing risk.")

    analysis.append(f"\nEmail Header Status: {'🚨 Not Safe' if any('[!' in line for line in analysis) else '✅ Safe'}")
    return "\n".join(analysis)

@app.route('/blacklist_lookup', methods=['GET', 'POST'])
@login_required
def blacklist_lookup():
    if request.method == 'GET':
        return render_template('blacklist.html')

    url = request.form.get('blacklist-url', '').strip()
    result = {}

    if url:
        try:
            prediction = predict_url(url)
            result['status'] = 'blacklisted' if prediction == 0 else 'not-blacklisted'
            result['message'] = 'Blacklisted ⚠️' if prediction == 0 else 'Not Blacklisted ✅'
        except Exception as e:
            result['status'] = 'error'
            result['message'] = f"Error: {str(e)}"
    else:
        result['status'] = 'error'
        result['message'] = "Please provide a valid URL."

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(result)
    else:
        return render_template('blacklist.html', result=result['message'])

@app.route('/ai_threat_detection', methods=['GET', 'POST'])
@login_required
def ai_threat_detection():
    if request.method == 'GET':
        return render_template('ai_based_detection.html')

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        url = request.form.get('ai-url', '').strip()
        result = {}

        if url:
            try:
                prediction = predict_url(url)
                result['status'] = 'error' if prediction == 0 else 'success'
                result['message'] = 'Threat Detected ⚠️' if prediction == 0 else 'URL Appears Safe ✅'
            except Exception as e:
                result['status'] = 'error'
                result['message'] = f"Error during detection: {str(e)}"
        else:
            result['status'] = 'error'
            result['message'] = 'Please enter a valid URL.'

        return jsonify(result)
    else:
        flash("Invalid access method. Please use the form.", "warning")
        return redirect(url_for('ai_threat_detection'))

@app.route('/url_analysis', methods=['GET', 'POST'])
@login_required
def url_analysis():
    if request.method == 'GET':
        return render_template('domain_rep.html')

    url = request.form.get('url', '').strip()
    result = {}

    if url:
        try:
            result['domain_reputation'] = domain_reputation(url)
            result['ssl_check'] = ssl_check(url)
        except Exception as e:
            result['error'] = f"Error analyzing URL: {str(e)}"
    else:
        result['error'] = "Please provide a valid URL."

    return jsonify(result)

def domain_reputation(url):
    try:
        domain = urlparse(url).netloc
        if not domain:
            return "Invalid URL: No domain found."

        w = whois.whois(domain)
        creation_date = w.get('creation_date')
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_days = (datetime.now() - creation_date).days if creation_date else None

        if age_days and age_days > 365:
            return f"Domain is {age_days} days old - looks trustworthy."
        else:
            return "Domain is new or creation date unknown - be cautious."
    except Exception as e:
        return f"Error fetching domain reputation: {str(e)}"

def ssl_check(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc or parsed_url.path
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expires - datetime.now()).days
                return f"SSL certificate is valid and expires in {days_left} days." if days_left > 30 else f"SSL certificate expires soon ({days_left} days left) or invalid."
    except Exception as e:
        return f"SSL check failed: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
