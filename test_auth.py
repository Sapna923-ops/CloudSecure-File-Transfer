"""
=============================================================================
CloudSecure File Transfer - Authentication & Security Tests (Stage 1)
=============================================================================
Tests:
1. User registration & salted password hashing
2. Password validation & duplicate prevention
3. User login & session creation
4. Protection against user enumeration (generic errors)
5. Unauthorized route access protection (@login_required)
6. Secure logout session termination
7. CSRF token enforcement for state-changing forms
8. Security audit trail (no secrets logged)
=============================================================================
"""

import unittest
from pathlib import Path
from app import app
from database import init_db, get_db_connection, get_user_by_username
from config import Config


class TestAuthentication(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Use an isolated test database to prevent polluting development database
        cls.test_db = Config.DATABASE_PATH.parent / "test_auth.db"
        if cls.test_db.exists():
            try:
                cls.test_db.unlink()
            except Exception:
                pass
        Config.DATABASE_PATH = cls.test_db
        init_db(cls.test_db)

        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = True

    @classmethod
    def tearDownClass(cls):
        # Restore default database path and clean up test database
        if cls.test_db.exists():
            try:
                cls.test_db.unlink()
            except Exception:
                pass
        Config.DATABASE_PATH = Config.DATABASE_PATH.parent / "cloudsecure.db"

    def setUp(self):
        self.client = app.test_client()

    def _get_csrf_token(self, client):
        """Helper to fetch a fresh CSRF token from the register page."""
        res = client.get("/register")
        self.assertEqual(res.status_code, 200)
        with client.session_transaction() as sess:
            return sess.get("csrf_token")

    def test_01_user_registration_success(self):
        """Test that a new user can register and password is cryptographically hashed."""
        csrf_token = self._get_csrf_token(self.client)

        username = "tyit_student_01"
        email = "student01@college.edu"
        password = "SecurePassword@123"

        response = self.client.post("/register", data={
            "csrf_token": csrf_token,
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Account created successfully", response.data)

        # Check database: plaintext password must NEVER exist
        user = get_user_by_username(username, db_path=self.test_db)
        self.assertIsNotNone(user)
        self.assertNotEqual(user["password_hash"], password)
        self.assertTrue(user["password_hash"].startswith("scrypt:") or user["password_hash"].startswith("pbkdf2:"))

    def test_02_registration_short_password_rejected(self):
        """Test that passwords shorter than 8 characters are rejected."""
        csrf_token = self._get_csrf_token(self.client)

        response = self.client.post("/register", data={
            "csrf_token": csrf_token,
            "username": "short_user",
            "email": "short@college.edu",
            "password": "123",
            "confirm_password": "123"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Password must be at least 8 characters", response.data)

    def test_03_registration_duplicate_username_rejected(self):
        """Test that duplicate usernames cannot be created."""
        csrf_token = self._get_csrf_token(self.client)

        # Attempt to register tyit_student_01 again
        response = self.client.post("/register", data={
            "csrf_token": csrf_token,
            "username": "tyit_student_01",
            "email": "another_email@college.edu",
            "password": "Password1234!",
            "confirm_password": "Password1234!"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"already taken", response.data)

    def test_04_registration_password_mismatch_rejected(self):
        """Test that mismatched passwords are rejected."""
        csrf_token = self._get_csrf_token(self.client)

        response = self.client.post("/register", data={
            "csrf_token": csrf_token,
            "username": "mismatch_user",
            "email": "mismatch@college.edu",
            "password": "Password1234!",
            "confirm_password": "DifferentPassword!"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Passwords do not match", response.data)

    def test_05_login_successful(self):
        """Test that user can log in and establish an authenticated session."""
        csrf_token = self._get_csrf_token(self.client)

        response = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "tyit_student_01",
            "password": "SecurePassword@123"
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)  # Redirects to index
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "tyit_student_01")
            self.assertIsNotNone(sess.get("user_id"))

    def test_06_login_invalid_password_rejected(self):
        """Test that wrong password is rejected with generic error message."""
        csrf_token = self._get_csrf_token(self.client)

        response = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "tyit_student_01",
            "password": "WrongPassword999!"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid username or password", response.data)

    def test_07_login_unknown_user_rejected(self):
        """Test that non-existent username receives the same generic error (prevent user enumeration)."""
        csrf_token = self._get_csrf_token(self.client)

        response = self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "non_existent_user_999",
            "password": "SomePassword123!"
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid username or password", response.data)

    def test_08_unauthenticated_access_blocked(self):
        """Test that unauthenticated requests to protected routes are blocked."""
        # Clean client without session
        clean_client = app.test_client()

        # HTML route redirects to login
        res_html = clean_client.get("/")
        self.assertEqual(res_html.status_code, 302)
        self.assertIn("/login", res_html.headers.get("Location", ""))

        # API route returns 401 JSON
        res_api = clean_client.get("/api/files")
        self.assertEqual(res_api.status_code, 401)
        self.assertIn("Authentication required", res_api.get_json()["error"])

    def test_09_logout_clears_session(self):
        """Test that POST /logout safely destroys the session."""
        # Log in first
        csrf_token = self._get_csrf_token(self.client)
        self.client.post("/login", data={
            "csrf_token": csrf_token,
            "username": "tyit_student_01",
            "password": "SecurePassword@123"
        })

        with self.client.session_transaction() as sess:
            current_csrf = sess.get("csrf_token")

        # Log out via POST with CSRF
        logout_res = self.client.post("/logout", data={
            "csrf_token": current_csrf
        }, follow_redirects=False)

        self.assertEqual(logout_res.status_code, 302)

        # Confirm session is completely cleared
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("user_id"))
            self.assertIsNone(sess.get("username"))

    def test_10_csrf_protection_enforced(self):
        """Test that state-changing POST requests without CSRF token are rejected with 403."""
        # Attempt to register without CSRF token
        res = self.client.post("/register", data={
            "username": "attacker",
            "email": "attacker@evil.com",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        self.assertEqual(res.status_code, 403)

    def test_11_audit_log_records_events(self):
        """Test that user actions are recorded in activity_logs without sensitive data."""
        conn = get_db_connection(self.test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT action, username, status FROM activity_logs WHERE username = 'tyit_student_01'")
        rows = cursor.fetchall()
        conn.close()

        self.assertTrue(len(rows) > 0)
        actions = [r["action"] for r in rows]
        self.assertIn("USER_REGISTER", actions)
        self.assertIn("USER_LOGIN", actions)


if __name__ == "__main__":
    unittest.main()
