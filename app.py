"""
=============================================================================
CloudSecure File Transfer - Main Flask Application (Stage 1: Auth & Accounts)
=============================================================================
A secure file transfer application implementing:
- User signup, login, and secure session management.
- Cryptographic password hashing (salted PBKDF2/scrypt).
- CSRF token protection for state-changing forms and AJAX calls.
- AES-256 authenticated encryption (Fernet).
- SHA-256 mathematical integrity verification.
- Local encrypted storage abstraction.
=============================================================================
"""

import io
import logging
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    flash,
    redirect,
    url_for,
    session,
)
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge, HTTPException

from config import Config
from security.crypto import (
    encrypt_bytes,
    decrypt_bytes,
    is_valid_key,
    DecryptionError,
    InvalidKeyError,
)
from security.integrity import compute_sha256, verify_sha256
from security.auth import (
    login_required,
    generate_csrf_token,
    check_csrf,
)
from database import (
    init_db,
    create_user,
    verify_user_credentials,
    log_activity,
    get_user_activity,
)
from storage.local_storage import LocalStorageManager

# Configure logging (Never log keys, passwords, or raw payloads)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
)
logger = logging.getLogger("CloudSecure")

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Database & Storage Engine
init_db(Config.DATABASE_PATH)
storage = LocalStorageManager()
storage.migrate_legacy_files(default_user_id=1, default_username="tyit_student_01")


@app.context_processor
def inject_globals():
    """Injects CSRF token generator into all Jinja templates automatically."""
    return dict(csrf_token=generate_csrf_token)


def is_allowed_file(filename: str) -> bool:
    """Checks if the uploaded file extension is in the whitelist."""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in Config.ALLOWED_EXTENSIONS


def is_safe_redirect_url(target: str) -> bool:
    """Validates that a redirect target is a safe relative path (Open Redirect mitigation)."""
    if not target or not isinstance(target, str):
        return False
    return target.startswith("/") and not target.startswith("//")


# ================= Error Handlers =================
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    """Gracefully handles files exceeding size limit without server crash."""
    logger.warning("Upload rejected: File size exceeded maximum limit.")
    return jsonify({
        "error": f"File is too large! Maximum allowed size is {Config.MAX_SIZE_MB} MB."
    }), 413


@app.errorhandler(403)
def handle_forbidden(e):
    """Handles CSRF token or permission failures without exposing stack trace."""
    msg = e.description if isinstance(e, HTTPException) else "Access Forbidden."
    if request.path.startswith("/api/") or request.is_json:
        return jsonify({"error": msg}), 403
    flash(f"Security Notice: {msg}", "danger")
    return render_template("login.html"), 403


@app.errorhandler(500)
def handle_server_error(e):
    """Catches internal errors without leaking sensitive stack traces."""
    logger.error("An internal server error occurred.")
    if request.path.startswith("/api/") or request.is_json:
        return jsonify({"error": "An internal server error occurred."}), 500
    return render_template("base.html"), 500


# ================= Authentication Routes =================
@app.route("/register", methods=["GET", "POST"])
def register():
    """Handles new user account registration."""
    # Redirect already authenticated users to dashboard
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if password != confirm_password:
            flash("Passwords do not match. Please verify and re-enter.", "danger")
            return render_template("register.html", username=username, email=email)

        try:
            user_id = create_user(username, email, password)
            log_activity(
                action="USER_REGISTER",
                username=username,
                status="SUCCESS",
                user_id=user_id,
                ip_address=request.remote_addr,
            )
            logger.info(f"New user registered successfully: {username}")
            flash("Account created successfully! Please sign in with your credentials.", "success")
            return redirect(url_for("login"))

        except ValueError as val_err:
            log_activity(
                action="REGISTER_FAILED",
                username=username or "unknown",
                status="FAILED",
                target_name=str(val_err),
                ip_address=request.remote_addr,
            )
            flash(str(val_err), "danger")
            return render_template("register.html", username=username, email=email)

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user sign in with salted cryptographic password verification."""
    # Redirect already authenticated users to dashboard
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = verify_user_credentials(username, password)

        if not user:
            # Generic error message to prevent user enumeration attacks
            log_activity(
                action="LOGIN_FAILED",
                username=username or "unknown",
                status="FAILED",
                ip_address=request.remote_addr,
            )
            logger.warning(f"Failed login attempt for username: {username}")
            flash("Invalid username or password.", "danger")
            return render_template("login.html", username=username)

        # Successful Login: Reset session to prevent session fixation attacks
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        # Ensure fresh CSRF token is issued for new authenticated session
        generate_csrf_token()

        log_activity(
            action="USER_LOGIN",
            username=user["username"],
            status="SUCCESS",
            user_id=user["id"],
            ip_address=request.remote_addr,
        )
        logger.info(f"User logged in successfully: {user['username']}")
        flash(f"Welcome back, {user['username']}!", "success")

        next_url = request.args.get("next")
        if next_url and is_safe_redirect_url(next_url):
            return redirect(next_url)
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    """Safely terminates the user session via POST request with CSRF protection."""
    check_csrf()
    username = session.get("username", "Anonymous")
    user_id = session.get("user_id")

    if user_id:
        log_activity(
            action="USER_LOGOUT",
            username=username,
            status="SUCCESS",
            user_id=user_id,
            ip_address=request.remote_addr,
        )
        logger.info(f"User logged out: {username}")

    session.clear()
    flash("You have been signed out safely.", "success")
    return redirect(url_for("login"))


# ================= Application & File Routes =================
@app.route("/")
@login_required
def index():
    """Renders the main CloudSecure dashboard for authenticated users."""
    key_configured = is_valid_key(Config.ENCRYPTION_KEY)
    current_user_id = session.get("user_id")
    files = storage.list_files_by_user(current_user_id)
    metrics = storage.get_user_storage_metrics(current_user_id)
    recent_activity = get_user_activity(current_user_id, limit=10)
    return render_template(
        "index.html",
        files=files,
        metrics=metrics,
        recent_activity=recent_activity,
        key_configured=key_configured,
        storage_mode=Config.STORAGE_MODE,
        max_size_mb=Config.MAX_SIZE_MB,
        allowed_extensions=sorted(list(Config.ALLOWED_EXTENSIONS))
    )


@app.route("/api/status", methods=["GET"])
def system_status():
    """Returns the operational and security status of the application."""
    user_id = session.get("user_id")
    user_files_count = len(storage.list_files_by_user(user_id)) if user_id else 0
    return jsonify({
        "status": "online",
        "storage_mode": Config.STORAGE_MODE,
        "encryption_key_configured": is_valid_key(Config.ENCRYPTION_KEY),
        "max_upload_size_mb": Config.MAX_SIZE_MB,
        "algorithm": "AES-128-CBC / Fernet + HMAC-SHA256",
        "integrity_check": "SHA-256",
        "authenticated": bool(user_id),
        "current_user": session.get("username"),
        "current_user_files": user_files_count,
        "total_files": len(storage.list_all_files())
    })


@app.route("/api/metrics", methods=["GET"])
@login_required
def get_metrics():
    """Returns storage metrics for the authenticated user."""
    current_user_id = session.get("user_id")
    return jsonify(storage.get_user_storage_metrics(current_user_id))


@app.route("/api/activity", methods=["GET"])
@login_required
def get_activity():
    """Returns security audit activity history for the authenticated user."""
    current_user_id = session.get("user_id")
    return jsonify(get_user_activity(current_user_id, limit=15))


@app.route("/api/files", methods=["GET"])
@login_required
def get_files():
    """Returns the JSON list of stored encrypted files belonging to the current user."""
    current_user_id = session.get("user_id")
    return jsonify(storage.list_files_by_user(current_user_id))


@app.route("/api/upload", methods=["POST"])
@login_required
def upload_file():
    """
    Secure file upload workflow (Authenticated):
    1. Verify CSRF token and authentication.
    2. Validate presence and sanitized filename.
    3. Validate allowed extension and file size.
    4. Compute plaintext SHA-256 checksum.
    5. Encrypt with Fernet (AES-128-CBC + HMAC-SHA256).
    6. Store ciphertext on disk with user ownership metadata.
    7. Record security audit log.
    """
    check_csrf()

    if not is_valid_key(Config.ENCRYPTION_KEY):
        logger.error("Upload rejected: Encryption key is not configured in .env.")
        return jsonify({
            "error": "Encryption key is missing or invalid! Run 'python generate_key.py' first."
        }), 500

    if "file" not in request.files:
        return jsonify({"error": "No file part in the request."}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    original_name = file.filename
    clean_name = secure_filename(original_name)
    if not clean_name:
        return jsonify({"error": "Invalid filename format."}), 400

    if not is_allowed_file(clean_name):
        return jsonify({
            "error": "File type not allowed. Permitted types include documents, images, and archives."
        }), 400

    try:
        file_bytes = file.read()
        file_size = len(file_bytes)

        if file_size == 0:
            return jsonify({"error": "The uploaded file is empty (0 bytes)."}), 400

        if file_size > Config.MAX_CONTENT_LENGTH:
            return jsonify({
                "error": f"File exceeds maximum limit of {Config.MAX_SIZE_MB} MB."
            }), 413

        # 1. Compute SHA-256 hash of original unencrypted file
        sha256_original = compute_sha256(file_bytes)

        # 2. Encrypt file bytes
        encrypted_bytes = encrypt_bytes(file_bytes, Config.ENCRYPTION_KEY)

        # 3. Compute SHA-256 hash of ciphertext
        sha256_encrypted = compute_sha256(encrypted_bytes)

        # 4. Save encrypted file in storage engine with ownership
        current_user_id = session.get("user_id")
        current_username = session.get("username", "Unknown")

        record = storage.save_encrypted_file(
            encrypted_bytes=encrypted_bytes,
            original_filename=clean_name,
            sha256_original=sha256_original,
            sha256_encrypted=sha256_encrypted,
            original_size=file_size,
            user_id=current_user_id,
            username=current_username,
        )

        # 5. Record Audit Log
        log_activity(
            action="FILE_UPLOAD",
            username=current_username,
            status="SUCCESS",
            user_id=current_user_id,
            target_name=clean_name,
            ip_address=request.remote_addr,
        )

        logger.info(f"File '{clean_name}' encrypted & saved by user '{current_username}' (ID: {current_user_id})")
        return jsonify({
            "message": "File encrypted and uploaded securely!",
            "file": record
        }), 201

    except InvalidKeyError as ike:
        logger.error("Upload error: Invalid key.")
        return jsonify({"error": str(ike)}), 500
    except Exception as exc:
        logger.error(f"Upload error: {str(exc)}")
        return jsonify({"error": "An unexpected server error occurred during upload."}), 500


@app.route("/api/download/<file_id>", methods=["GET"])
@login_required
def download_file(file_id: str):
    """
    Secure download workflow with IDOR prevention:
    1. Retrieve metadata and verify requesting user ownership.
    2. Decrypt in memory.
    3. Verify SHA-256 integrity checksum.
    4. Stream plaintext directly to client (never written unencrypted to disk).
    5. Record audit entry.
    """
    if not is_valid_key(Config.ENCRYPTION_KEY):
        return jsonify({"error": "Encryption key is missing or invalid."}), 500

    metadata = storage.get_file_metadata(file_id)
    if not metadata:
        return jsonify({"error": "File record not found."}), 404

    # IDOR Access Control Guard
    current_user_id = session.get("user_id")
    if metadata.get("user_id") != current_user_id:
        log_activity(
            action="UNAUTHORIZED_DOWNLOAD_ATTEMPT",
            username=session.get("username", "Unknown"),
            status="BLOCKED",
            user_id=current_user_id,
            target_name=metadata.get("original_filename", file_id),
            ip_address=request.remote_addr,
        )
        logger.warning(
            f"IDOR attempt blocked: User {current_user_id} tried to download file {file_id} owned by {metadata.get('user_id')}"
        )
        return jsonify({"error": "Access denied. You do not have permission to download this file."}), 403

    encrypted_bytes = storage.get_encrypted_file(file_id)
    if encrypted_bytes is None:
        return jsonify({"error": "Encrypted file data is missing on disk."}), 404

    try:
        decrypted_bytes = decrypt_bytes(encrypted_bytes, Config.ENCRYPTION_KEY)

        expected_hash = metadata.get("sha256_original", "")
        if not verify_sha256(decrypted_bytes, expected_hash):
            logger.critical(f"INTEGRITY VIOLATION DETECTED for file ID {file_id}!")
            log_activity(
                action="INTEGRITY_VIOLATION",
                username=session.get("username", "Unknown"),
                status="FAILED",
                user_id=current_user_id,
                target_name=metadata["original_filename"],
                ip_address=request.remote_addr,
            )
            return jsonify({
                "error": "SECURITY WARNING: SHA-256 Integrity Verification Failed! File has been altered or corrupted."
            }), 400

        log_activity(
            action="FILE_DOWNLOAD",
            username=session.get("username", "Unknown"),
            status="SUCCESS",
            user_id=current_user_id,
            target_name=metadata["original_filename"],
            ip_address=request.remote_addr,
        )

        return send_file(
            io.BytesIO(decrypted_bytes),
            as_attachment=True,
            download_name=metadata["original_filename"],
            mimetype="application/octet-stream"
        )

    except DecryptionError as de:
        logger.error(f"Decryption failed for {file_id}: {str(de)}")
        return jsonify({"error": str(de)}), 400
    except Exception as exc:
        logger.error(f"Unexpected download error: {str(exc)}")
        return jsonify({"error": "Could not complete secure download."}), 500


@app.route("/api/verify/<file_id>", methods=["GET"])
@login_required
def verify_file_integrity(file_id: str):
    """
    Live Integrity Verification Endpoint with IDOR protection:
    Decrypts in memory and calculates SHA-256 checksum to compare against original hash.
    """
    if not is_valid_key(Config.ENCRYPTION_KEY):
        return jsonify({"error": "Encryption key is missing or invalid."}), 500

    metadata = storage.get_file_metadata(file_id)
    if not metadata:
        return jsonify({"error": "File not found."}), 404

    # IDOR Access Control Guard
    current_user_id = session.get("user_id")
    if metadata.get("user_id") != current_user_id:
        log_activity(
            action="UNAUTHORIZED_VERIFY_ATTEMPT",
            username=session.get("username", "Unknown"),
            status="BLOCKED",
            user_id=current_user_id,
            target_name=metadata.get("original_filename", file_id),
            ip_address=request.remote_addr,
        )
        logger.warning(
            f"IDOR attempt blocked: User {current_user_id} tried to verify file {file_id} owned by {metadata.get('user_id')}"
        )
        return jsonify({
            "error": "Access denied. You do not have permission to verify this file.",
            "status": "BLOCKED"
        }), 403

    encrypted_bytes = storage.get_encrypted_file(file_id)
    if encrypted_bytes is None:
        return jsonify({"error": "Encrypted file missing on disk."}), 404

    try:
        decrypted_bytes = decrypt_bytes(encrypted_bytes, Config.ENCRYPTION_KEY)
        computed_hash = compute_sha256(decrypted_bytes)
        expected_hash = metadata.get("sha256_original", "")
        matches = verify_sha256(decrypted_bytes, expected_hash)

        log_activity(
            action="INTEGRITY_VERIFY",
            username=session.get("username", "Unknown"),
            status="PASS" if matches else "FAIL",
            user_id=current_user_id,
            target_name=metadata["original_filename"],
            ip_address=request.remote_addr,
        )

        return jsonify({
            "filename": metadata["original_filename"],
            "stored_filename": metadata["stored_filename"],
            "sha256_original": expected_hash,
            "sha256_calculated_now": computed_hash,
            "sha256_encrypted": metadata.get("sha256_encrypted"),
            "integrity_matched": matches,
            "status": "PASS" if matches else "FAIL",
            "message": "SHA-256 cryptographic check PASSED. Data is 100% intact." if matches else "Integrity check FAILED!"
        })
    except DecryptionError as de:
        return jsonify({"error": str(de), "status": "FAIL"}), 400
    except Exception as exc:
        return jsonify({"error": str(exc), "status": "ERROR"}), 500


@app.route("/api/delete/<file_id>", methods=["DELETE"])
@login_required
def delete_file(file_id: str):
    """Deletes an encrypted file and its metadata record with IDOR protection."""
    check_csrf()
    metadata = storage.get_file_metadata(file_id)
    if not metadata:
        return jsonify({"error": "File not found or could not be deleted."}), 404

    # IDOR Access Control Guard
    current_user_id = session.get("user_id")
    if metadata.get("user_id") != current_user_id:
        log_activity(
            action="UNAUTHORIZED_DELETE_ATTEMPT",
            username=session.get("username", "Unknown"),
            status="BLOCKED",
            user_id=current_user_id,
            target_name=metadata.get("original_filename", file_id),
            ip_address=request.remote_addr,
        )
        logger.warning(
            f"IDOR attempt blocked: User {current_user_id} tried to delete file {file_id} owned by {metadata.get('user_id')}"
        )
        return jsonify({"error": "Access denied. You do not have permission to delete this file."}), 403

    target_name = metadata.get("original_filename", file_id)
    success = storage.delete_file(file_id, user_id=current_user_id)
    if success:
        log_activity(
            action="FILE_DELETE",
            username=session.get("username", "Unknown"),
            status="SUCCESS",
            user_id=current_user_id,
            target_name=target_name,
            ip_address=request.remote_addr,
        )
        logger.info(f"Deleted file: {target_name} by user {current_user_id}")
        return jsonify({"message": "File deleted successfully."})

    return jsonify({"error": "File not found or could not be deleted."}), 404


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  CloudSecure File Transfer Server Starting (Stage 1)")
    print("  Local URL: http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
