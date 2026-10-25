"""
Deliberately vulnerable Python app for testing SecureScope.
DO NOT use this code in production — it contains intentional security flaws.
"""

import os
import hashlib
import pickle
import subprocess
import sqlite3
import yaml
import requests

# ═══════════════════════════════════════════════════════════════
# A01 — Broken Access Control
# ═══════════════════════════════════════════════════════════════

def get_user_file(user_input):
    """Path traversal — no validation on user input."""
    filepath = "/data/uploads/" + user_input
    with open(filepath, "r") as f:
        return f.read()


# ═══════════════════════════════════════════════════════════════
# A02 — Cryptographic Failures
# ═══════════════════════════════════════════════════════════════

DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

def hash_password(password):
    """Using MD5 for password hashing — critically weak."""
    return hashlib.md5(password.encode()).hexdigest()

def weak_hash(data):
    """Using SHA1 — known to be broken."""
    return hashlib.sha1(data.encode()).hexdigest()


# ═══════════════════════════════════════════════════════════════
# A03 — Injection
# ═══════════════════════════════════════════════════════════════

def search_users(username):
    """SQL injection via string formatting."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchall()

def run_command(user_input):
    """Command injection via os.system."""
    os.system(f"echo {user_input}")

def run_shell(cmd):
    """Command injection via subprocess with shell=True."""
    subprocess.call(cmd, shell=True)

def dangerous_eval(expression):
    """Code injection via eval."""
    return eval(expression)


# ═══════════════════════════════════════════════════════════════
# A05 — Security Misconfiguration
# ═══════════════════════════════════════════════════════════════

DEBUG = True
VERBOSE_ERRORS = True


# ═══════════════════════════════════════════════════════════════
# A07 — Authentication Failures
# ═══════════════════════════════════════════════════════════════

def fetch_insecure(url):
    """Disabled SSL verification."""
    return requests.get(url, verify=False)


# ═══════════════════════════════════════════════════════════════
# A08 — Data Integrity Failures
# ═══════════════════════════════════════════════════════════════

def load_data(data_bytes):
    """Insecure deserialization with pickle."""
    return pickle.loads(data_bytes)

def load_yaml_config(yaml_string):
    """Unsafe YAML loading without SafeLoader."""
    return yaml.load(yaml_string)


# ═══════════════════════════════════════════════════════════════
# A10 — SSRF
# ═══════════════════════════════════════════════════════════════

def fetch_url(user_url):
    """SSRF — fetching user-controlled URLs without validation."""
    response = requests.get(user_url)
    return response.text


# ═══════════════════════════════════════════════════════════════
# Connection string with embedded credentials
# ═══════════════════════════════════════════════════════════════

DB_URI = "postgresql://admin:p@ssw0rd123@10.0.1.50:5432/production_db"
REDIS_URL = "redis://default:my_redis_pass@192.168.1.100:6379/0"
