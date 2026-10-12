"""
=============================================================================
CloudSecure File Transfer - SQLite Database Manager
=============================================================================
Manages user accounts, salted cryptographic password hashing,
and non-sensitive security audit logging.

Security Best Practices:
1. Parameterized SQL Queries: Prevents SQL Injection attacks.
2. Cryptographic Password Hashing: Uses Werkzeug's default salted hash (scrypt or PBKDF2),
   meaning plaintext passwords are NEVER stored on disk.
3. Sanitized Audit Logging: Stores actions and timestamps without ever logging
   passwords, encryption keys, or decrypted file contents.
=============================================================================
"""

import sqlite3
import re
from pathlib import Path
from typing import Optional, List, Dict
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Creates a connection to the SQLite database with Row support."""
    path = Path(db_path or Config.DATABASE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Initializes SQLite schema for users and security audit logs."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Activity / Audit History Table
    # NOTE: Never records secret keys, passwords, or decrypted payloads!
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target_name TEXT,
            status TEXT NOT NULL,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    conn.commit()
    conn.close()


def validate_username(username: str) -> bool:
    """Validates that username contains only letters, numbers, and underscores (3-30 chars)."""
    if not username or not isinstance(username, str):
        return False
    return bool(re.match(r"^[a-zA-Z0-9_]{3,30}$", username))


def validate_email(email: str) -> bool:
    """Basic format check for email address."""
    if not email or not isinstance(email, str):
        return False
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def create_user(username: str, email: str, password: str, db_path: Optional[Path] = None) -> int:
    """
    Registers a new user with a salted cryptographic password hash.

    Parameters:
        username (str): Desired username.
        email (str): Contact email.
        password (str): Plaintext password from registration form.

    Returns:
        int: The newly created user ID.

    Raises:
        ValueError: If validation fails or username/email already exists.
    """
    username = username.strip()
    email = email.strip()

    if not validate_username(username):
        raise ValueError("Username must be between 3 and 30 characters and contain only letters, numbers, or underscores.")

    if not validate_email(email):
        raise ValueError("Please provide a valid email address.")

    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long for adequate security.")

    # Generate salted cryptographic hash
    pw_hash = generate_password_hash(password)

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, pw_hash)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError as err:
        err_msg = str(err).lower()
        if "username" in err_msg:
            raise ValueError("That username is already taken. Please choose another.")
        elif "email" in err_msg:
            raise ValueError("An account with that email already exists.")
        else:
            raise ValueError("User registration failed due to duplicate information.")
    finally:
        conn.close()


def get_user_by_username(username: str, db_path: Optional[Path] = None) -> Optional[dict]:
    """Retrieves a user record by username."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, password_hash, created_at FROM users WHERE username = ?", (username.strip(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int, db_path: Optional[Path] = None) -> Optional[dict]:
    """Retrieves a user record by user ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, created_at FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def verify_user_credentials(username: str, password: str, db_path: Optional[Path] = None) -> Optional[dict]:
    """
    Verifies user login credentials using timing-attack safe password verification.

    Returns:
        dict: User dictionary without password_hash if valid, None if invalid.
    """
    user = get_user_by_username(username, db_path)
    if not user:
        return None

    if check_password_hash(user["password_hash"], password):
        # Remove hash before returning to caller
        user.pop("password_hash", None)
        return user

    return None


def log_activity(
    action: str,
    username: str,
    status: str = "SUCCESS",
    user_id: Optional[int] = None,
    target_name: Optional[str] = None,
    ip_address: Optional[str] = None,
    db_path: Optional[Path] = None
) -> None:
    """
    Records an entry in the security audit history.
    NEVER logs passwords, encryption keys, or sensitive payload data.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO activity_logs (user_id, username, action, target_name, status, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, action, target_name or "", status, ip_address or "")
        )
        conn.commit()
    except Exception:
        # Failure to write an audit entry must not crash user operations
        pass
    finally:
        conn.close()


def get_user_activity(user_id: int, limit: int = 15, db_path: Optional[Path] = None) -> List[dict]:
    """Fetches recent activity logs for a specific user."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, action, target_name, status, timestamp
        FROM activity_logs
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (user_id, limit)
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
