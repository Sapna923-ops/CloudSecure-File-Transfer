"""
=============================================================================
CloudSecure File Transfer - Configuration Module
=============================================================================
Manages environment variables, security constraints, and upload directories.
=============================================================================
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env file
load_dotenv(dotenv_path=BASE_DIR / ".env")


class Config:
    """Base application configuration with security defaults."""

    # Flask Secret Key for session signing and CSRF
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-please-change-in-production")

    # SQLite Database Configuration
    DATABASE_PATH = BASE_DIR / "database" / "cloudsecure.db"

    # Secure Session Cookie Settings
    # HttpOnly: Blocks client-side JavaScript from reading cookies (XSS mitigation)
    SESSION_COOKIE_HTTPONLY = True
    # SameSite=Lax: Protects against Cross-Site Request Forgery (CSRF)
    SESSION_COOKIE_SAMESITE = "Lax"
    # Secure: Transmit cookie only over HTTPS in production; False in local dev for HTTP
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour in seconds

    # Local uploads directory
    UPLOAD_FOLDER = BASE_DIR / "uploads"
    METADATA_FILE = UPLOAD_FOLDER / "metadata.json"

    # Maximum file size allowed for upload
    MAX_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", 16))
    MAX_CONTENT_LENGTH = MAX_SIZE_MB * 1024 * 1024  # e.g., 16 MB in bytes

    # Allowed file extensions to prevent malicious executable files (.exe, .bat, .sh, etc.)
    ALLOWED_EXTENSIONS = {
        "txt", "pdf", "png", "jpg", "jpeg", "gif", "svg",
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv",
        "zip", "tar", "gz", "7z", "json", "xml", "md", "mp3", "mp4"
    }

    # Cryptographic Key for AES/Fernet encryption
    ENCRYPTION_KEY = os.getenv("SECRET_ENCRYPTION_KEY", "")

    # Storage Mode: 'local' (₹0 local testing) or 's3' (AWS Cloud)
    STORAGE_MODE = os.getenv("STORAGE_MODE", "local").lower()

    # AWS S3 Settings (Phase 2)
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
    AWS_S3_BUCKET_NAME = os.getenv("AWS_S3_BUCKET_NAME", "")
