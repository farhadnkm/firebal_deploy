"""
auth.py — Authentication utilities and database helpers.
"""
import sqlite3
import bcrypt
from datetime import datetime, timedelta
import secrets
import os

DB_PATH = os.environ.get("AUTH_DB_PATH", "app.db")

def get_db():
    """Get SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database schema."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reset_tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash."""
    return bcrypt.checkpw(password.encode(), password_hash.encode())

def create_user(username: str, password: str) -> dict:
    """Create a new user."""
    conn = get_db()
    try:
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password))
        )
        conn.commit()
        user_id = cursor.lastrowid
        return {"id": user_id, "username": username}
    except sqlite3.IntegrityError:
        raise ValueError(f"Username '{username}' already exists")
    finally:
        conn.close()

def get_user_by_username(username: str) -> dict | None:
    """Fetch user by username."""
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None

def authenticate_user(username: str, password: str) -> dict | None:
    """Authenticate user; return user dict if valid, else None."""
    user = get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user

def create_session(user_id: int, expires_in_hours: int = 24) -> str:
    """Create a session; return session_id."""
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
    
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)",
        (session_id, user_id, expires_at)
    )
    conn.commit()
    conn.close()
    return session_id

def validate_session(session_id: str) -> dict | None:
    """Validate session; return user dict if valid, else None."""
    conn = get_db()
    result = conn.execute(
        """SELECT s.session_id, s.user_id, u.username
           FROM sessions s
           JOIN users u ON s.user_id = u.id
           WHERE s.session_id = ? AND s.expires_at > CURRENT_TIMESTAMP""",
        (session_id,)
    ).fetchone()
    conn.close()
    return dict(result) if result else None

def revoke_session(session_id: str):
    """Delete a session."""
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
    conn.commit()
    conn.close()

def create_reset_token(user_id: int, expires_in_minutes: int = 60) -> str:
    """Create a password reset token."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
    
    conn = get_db()
    conn.execute(
        "INSERT INTO reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires_at)
    )
    conn.commit()
    conn.close()
    return token

def validate_reset_token(token: str) -> dict | None:
    """Validate reset token; return {token, user_id} if valid, else None."""
    conn = get_db()
    result = conn.execute(
        """SELECT token, user_id FROM reset_tokens
           WHERE token = ? AND used = 0 AND expires_at > CURRENT_TIMESTAMP""",
        (token,)
    ).fetchone()
    conn.close()
    return dict(result) if result else None

def use_reset_token(token: str, new_password: str) -> bool:
    """Mark token as used and update password."""
    conn = get_db()
    
    result = conn.execute(
        "SELECT user_id FROM reset_tokens WHERE token = ? AND used = 0",
        (token,)
    ).fetchone()
    
    if not result:
        conn.close()
        return False
    
    user_id = result[0]
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (hash_password(new_password), user_id)
    )
    conn.execute(
        "UPDATE reset_tokens SET used = 1 WHERE token = ?",
        (token,)
    )
    conn.commit()
    conn.close()
    return True
