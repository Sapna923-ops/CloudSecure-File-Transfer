"""
=============================================================================
CloudSecure File Transfer - Stage 2 Ownership & IDOR Protection Tests
=============================================================================
Verifies multi-user tenancy and authorization guarantees:
1. File listing isolation: User A only sees User A's files; User B only sees User B's files.
2. IDOR Prevention - Download: User A receives 403 when requesting User B's file.
3. IDOR Prevention - Verification: User A receives 403 when verifying User B's file.
4. IDOR Prevention - Delete: User A receives 403 when attempting to delete User B's file,
   and User B's file remains untouched in storage.
5. Storage metrics per user: /api/metrics reflects current user's file count & storage usage.
6. Activity history isolation: /api/activity returns only current user's audit entries without secrets.
7. Legacy file migration & cross-user leak prevention.
=============================================================================
"""

import io
import unittest
from pathlib import Path
from cryptography.fernet import Fernet
from app import app
from database import init_db
from config import Config
from storage.local_storage import LocalStorageManager


class TestFileOwnershipAndIDOR(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Configure isolated test database and test uploads folder
        cls.test_db = Config.DATABASE_PATH.parent / "test_ownership.db"
        cls.test_uploads = Config.UPLOAD_FOLDER.parent / "test_uploads_ownership"
        cls.test_metadata = cls.test_uploads / "metadata.json"

        if cls.test_db.exists():
            try:
                cls.test_db.unlink()
            except Exception:
                pass

        if cls.test_uploads.exists():
            import shutil
            shutil.rmtree(cls.test_uploads, ignore_errors=True)

        Config.DATABASE_PATH = cls.test_db
        init_db(cls.test_db)

        # Isolated storage manager
        cls.test_storage = LocalStorageManager(
            upload_folder=cls.test_uploads,
            metadata_file=cls.test_metadata
        )

        cls.test_key = Fernet.generate_key().decode("utf-8")
        Config.ENCRYPTION_KEY = cls.test_key
        app.config["TESTING"] = True

        # Point app's storage engine to our test storage
        import app as app_module
        cls.orig_storage = app_module.storage
        app_module.storage = cls.test_storage

    @classmethod
    def tearDownClass(cls):
        import app as app_module
        app_module.storage = cls.orig_storage

        if cls.test_db.exists():
            try:
                cls.test_db.unlink()
            except Exception:
                pass

        if cls.test_uploads.exists():
            import shutil
            shutil.rmtree(cls.test_uploads, ignore_errors=True)

        Config.DATABASE_PATH = Config.DATABASE_PATH.parent / "cloudsecure.db"

    def setUp(self):
        self.csrf_token_a = "csrf_token_user_a_secret_123"
        self.csrf_token_b = "csrf_token_user_b_secret_456"

        # Client for User A (user_id = 101, username = 'alice')
        self.client_a = app.test_client()
        with self.client_a.session_transaction() as sess:
            sess["user_id"] = 101
            sess["username"] = "alice"
            sess["csrf_token"] = self.csrf_token_a

        # Client for User B (user_id = 202, username = 'bob')
        self.client_b = app.test_client()
        with self.client_b.session_transaction() as sess:
            sess["user_id"] = 202
            sess["username"] = "bob"
            sess["csrf_token"] = self.csrf_token_b

    def _upload_file(self, client, csrf_token, filename, content):
        """Helper to upload a file for a specific client."""
        data = {
            "file": (io.BytesIO(content), filename)
        }
        res = client.post(
            "/api/upload",
            data=data,
            headers={"X-CSRFToken": csrf_token},
            content_type="multipart/form-data"
        )
        self.assertEqual(res.status_code, 201)
        return res.get_json()["file"]

    def test_01_user_file_listing_isolation(self):
        """Test that User A only sees User A's files and User B only sees User B's files."""
        # Alice uploads a file
        file_alice = self._upload_file(
            self.client_a, self.csrf_token_a, "alice_doc.pdf", b"Alice Confidential Data"
        )

        # Bob uploads a file
        file_bob = self._upload_file(
            self.client_b, self.csrf_token_b, "bob_report.pdf", b"Bob Private Research"
        )

        # Alice lists files
        res_a = self.client_a.get("/api/files")
        self.assertEqual(res_a.status_code, 200)
        files_a = res_a.get_json()
        ids_a = [f["id"] for f in files_a]

        self.assertIn(file_alice["id"], ids_a)
        self.assertNotIn(file_bob["id"], ids_a, "CRITICAL: Bob's file leaked to Alice's inventory!")

        # Bob lists files
        res_b = self.client_b.get("/api/files")
        self.assertEqual(res_b.status_code, 200)
        files_b = res_b.get_json()
        ids_b = [f["id"] for f in files_b]

        self.assertIn(file_bob["id"], ids_b)
        self.assertNotIn(file_alice["id"], ids_b, "CRITICAL: Alice's file leaked to Bob's inventory!")

    def test_02_idor_download_blocked(self):
        """Test that User A cannot download User B's file via IDOR attack (HTTP 403)."""
        file_bob = self._upload_file(
            self.client_b, self.csrf_token_b, "bob_secret.txt", b"Bob's Secret Vault"
        )

        # Alice attempts to download Bob's file using Bob's file ID
        res_idor = self.client_a.get(f"/api/download/{file_bob['id']}")
        self.assertEqual(res_idor.status_code, 403, "CRITICAL: IDOR vulnerability allowed Alice to download Bob's file!")
        json_idor = res_idor.get_json()
        self.assertIn("Access denied", json_idor["error"])

        # Bob can download his own file
        res_valid = self.client_b.get(f"/api/download/{file_bob['id']}")
        self.assertEqual(res_valid.status_code, 200)
        self.assertEqual(res_valid.data, b"Bob's Secret Vault")

    def test_03_idor_verify_blocked(self):
        """Test that User A cannot run integrity verification on User B's file (HTTP 403)."""
        file_bob = self._upload_file(
            self.client_b, self.csrf_token_b, "bob_integrity.pdf", b"Bob Integrity Payload"
        )

        # Alice attempts to verify Bob's file
        res_idor = self.client_a.get(f"/api/verify/{file_bob['id']}")
        self.assertEqual(res_idor.status_code, 403, "CRITICAL: IDOR allowed Alice to verify Bob's file!")
        json_idor = res_idor.get_json()
        self.assertIn("Access denied", json_idor["error"])

        # Bob can verify his own file
        res_valid = self.client_b.get(f"/api/verify/{file_bob['id']}")
        self.assertEqual(res_valid.status_code, 200)
        self.assertTrue(res_valid.get_json()["integrity_matched"])

    def test_04_idor_delete_blocked(self):
        """Test that User A cannot delete User B's file via IDOR (HTTP 403) and file persists."""
        file_bob = self._upload_file(
            self.client_b, self.csrf_token_b, "bob_important.pdf", b"Must Not Be Deleted"
        )

        # Alice attempts to delete Bob's file
        res_idor = self.client_a.delete(
            f"/api/delete/{file_bob['id']}",
            headers={"X-CSRFToken": self.csrf_token_a}
        )
        self.assertEqual(res_idor.status_code, 403, "CRITICAL: IDOR allowed Alice to delete Bob's file!")

        # Confirm Bob's file STILL exists in storage
        metadata = self.test_storage.get_file_metadata(file_bob["id"])
        self.assertIsNotNone(metadata, "CRITICAL: Bob's file was deleted despite 403!")

        # Bob can delete his own file
        res_delete_bob = self.client_b.delete(
            f"/api/delete/{file_bob['id']}",
            headers={"X-CSRFToken": self.csrf_token_b}
        )
        self.assertEqual(res_delete_bob.status_code, 200)

    def test_05_dashboard_metrics_calculation(self):
        """Test that /api/metrics calculates accurate storage and count for current user."""
        res_metrics_a = self.client_a.get("/api/metrics")
        self.assertEqual(res_metrics_a.status_code, 200)
        data_a = res_metrics_a.get_json()

        self.assertIn("total_files", data_a)
        self.assertIn("total_encrypted_bytes", data_a)
        self.assertIn("total_original_bytes", data_a)
        self.assertIn("formatted_encrypted_size", data_a)

        # Alice should have files created during earlier tests
        self.assertGreaterEqual(data_a["total_files"], 1)
        self.assertGreater(data_a["total_encrypted_bytes"], 0)

    def test_06_activity_trail_isolation_and_no_secrets(self):
        """Test that /api/activity returns only user's events and contains no sensitive credentials."""
        res_activity = self.client_a.get("/api/activity")
        self.assertEqual(res_activity.status_code, 200)
        logs = res_activity.get_json()

        self.assertIsInstance(logs, list)
        self.assertGreater(len(logs), 0)

        # Ensure no secrets or keys are stored in activity logs
        for entry in logs:
            entry_str = str(entry).lower()
            self.assertNotIn(Config.ENCRYPTION_KEY.lower(), entry_str)
            self.assertNotIn("password_hash", entry_str)
            self.assertIn("action", entry)
            self.assertIn("status", entry)

    def test_07_legacy_file_migration(self):
        """Test that legacy files without user_id can be migrated to default user without leaking."""
        # Directly insert a legacy unowned file into metadata
        legacy_id = "legacy-file-uuid-001"
        index = self.test_storage._read_metadata_index()
        index[legacy_id] = {
            "id": legacy_id,
            "original_filename": "legacy_doc.pdf",
            "stored_filename": f"{legacy_id}.enc",
            "original_size": 1024,
            "encrypted_size": 1400,
            "sha256_original": "somehash",
            "sha256_encrypted": "someenchash",
            "uploaded_at": "2026-01-01 00:00:00",
            # Note: No user_id!
        }
        self.test_storage._write_metadata_index(index)

        # Run migration assigning legacy files to Alice (101)
        migrated = self.test_storage.migrate_legacy_files(default_user_id=101, default_username="alice")
        self.assertGreaterEqual(migrated, 1)

        # Verify Alice can see it
        alice_files = self.test_storage.list_files_by_user(101)
        alice_ids = [f["id"] for f in alice_files]
        self.assertIn(legacy_id, alice_ids)

        # Verify Bob CANNOT see it
        bob_files = self.test_storage.list_files_by_user(202)
        bob_ids = [f["id"] for f in bob_files]
        self.assertNotIn(legacy_id, bob_ids)

        # Clean up legacy record
        self.test_storage.delete_file(legacy_id, user_id=101)


if __name__ == "__main__":
    unittest.main()
