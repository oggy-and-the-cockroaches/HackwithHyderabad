"""Test FastAPI application with intentional security and privacy issues."""

import os
import sqlite3
import logging
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import bcrypt

# HARDCODED SECRETS - CRITICAL ISSUES
API_KEY = "sk_test_placeholder_key_for_testing_12345"
SECRET_KEY = "my-super-secret-jwt-key-do-not-share"
DATABASE_PASSWORD = "admin123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Debug mode enabled - HIGH ISSUE
DEBUG = True

app = FastAPI(debug=True, title="Test App")

# Missing security headers middleware
# No rate limiting
# Unsafe CORS
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sensitive data in logs - MEDIUM ISSUE
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.info(f"Starting app with API_KEY={API_KEY}")

class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# SQL Injection vulnerability - HIGH ISSUE
def get_user_by_email_unsafe(email: str):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # UNSAFE: String concatenation
    query = f"SELECT * FROM users WHERE email = '{email}'"
    cursor.execute(query)
    return cursor.fetchone()

# Safe version for comparison
def get_user_by_email_safe(email: str):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # SAFE: Parameterized query
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cursor.fetchone()

# Command injection vulnerability - HIGH ISSUE
import subprocess
def run_command_unsafe(user_input: str):
    # UNSAFE: Shell injection
    result = subprocess.run(f"echo {user_input}", shell=True, capture_output=True, text=True)
    return result.stdout

# XSS vulnerability - MEDIUM ISSUE
@app.get("/unsafe-render/{user_input}")
def unsafe_render(user_input: str):
    # UNSAFE: Direct HTML rendering
    return HTMLResponse(f"<h1>Welcome {user_input}</h1>")

# Missing authentication on sensitive endpoint - HIGH ISSUE
@app.get("/admin/users")
def admin_users():
    # No authentication check!
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users")
    return {"users": [row[0] for row in cursor.fetchall()]}

# Weak password handling - HIGH ISSUE
def hash_password_weak(password: str):
    # Using MD5 - very weak!
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

# JWT with none algorithm - CRITICAL ISSUE
import jwt
def create_token_none_algorithm(user_id: int):
    # CRITICAL: Using 'none' algorithm
    return jwt.encode({"user_id": user_id}, "", algorithm="none")

# Missing input validation - MEDIUM ISSUE
@app.post("/users")
def create_user(user: UserCreate):
    # No validation on email/password
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # SQL injection here too
    cursor.execute(f"INSERT INTO users (email, password) VALUES ('{user.email}', '{user.password}')")
    conn.commit()
    return {"message": "User created"}

# Unsafe error handling - MEDIUM ISSUE
@app.get("/error")
def trigger_error():
    # This will expose stack trace
    raise ValueError("This is a test error with sensitive info: " + API_KEY)

# Login with SQL injection - HIGH ISSUE
@app.post("/login")
def login(user: UserLogin):
    # SQL injection in login
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE email = '{user.email}' AND password = '{user.password}'")
    result = cursor.fetchone()
    if result:
        return {"token": "fake-jwt-token"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

# Health check - GOOD
@app.get("/health")
def health():
    return {"status": "healthy"}

# Missing 404 handler - RELIABILITY ISSUE
# No custom 404 page

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)