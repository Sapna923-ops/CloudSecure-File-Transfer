"""
=============================================================================
CloudSecure File Transfer - Automated Unit & Integration Tests
=============================================================================
Verifies all security promises:
1. Key generation & validation
2. Fernet AES-128-CBC encryption and decryption
3. Tamper detection (cryptographic failure when ciphertext is altered)
4. SHA-256 checksum calculation & integrity verification
5. Flask upload, download, and verification endpoints (authenticated session)
6. Security enforcement (rejection of malicious/empty files)
=============================================================================
"""

import io
import unittest
from cryptography.fernet import Fernet
from security.crypto import encrypt_bytes, decrypt_bytes, is_valid_key, DecryptionError
from security.integrity import compute_sha256, verify_sha256
from app import app
from config import Config


class TestCloudSecure(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Generate a test key
        cls.test_key = Fernet.generate_key().decode("utf-8")
        Config.ENCRYPTION_KEY = cls.test_key
        app.config["TESTING"] = True
        cls.client = app.test_client()

        # Set up an authenticated session with CSRF token for file tests
        cls.csrf_token = "test_csrf_token_secret_123"
        with cls.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "test_operator"
            sess["csrf_token"] = cls.csrf_token

    def test_01_key_validation(self):
        """Test that key validation correctly accepts valid Fernet keys and rejects invalid ones."""
        self.assertTrue(is_valid_key(self.test_key))
        self.assertFalse(is_valid_key("short-invalid-key"))
        self.assertFalse(is_valid_key(""))
        self.assertFalse(is_valid_key(None))

    def test_02_encryption_and_decryption(self):
        """Test that data can be encrypted and accurately decrypted."""
        original_data = b"Welcome to TYIT Cloud Computing Secure File Transfer!"
        encrypted = encrypt_bytes(original_data, self.test_key)

        # Ciphertext must not match original plaintext
        self.assertNotEqual(original_data, encrypted)

        # Decrypted content must match original exactly
        decrypted = decrypt_bytes(encrypted, self.test_key)
        self.assertEqual(original_data, decrypted)

    def test_03_tamper_detection(self):
        """Test that modifying even a single byte in ciphertext triggers DecryptionError."""
        original_data = b"Confidential cloud storage payload"
        encrypted = encrypt_bytes(original_data, self.test_key)

        # Tamper with the ciphertext by flipping bytes
        tampered_byte = bytes([encrypted[20] ^ 0xFF])
        tampered_encrypted = encrypted[:20] + tampered_byte + encrypted[21:]

        with self.assertRaises(DecryptionError):
            decrypt_bytes(tampered_encrypted, self.test_key)

    def test_04_sha256_integrity(self):
        """Test SHA-256 hashing and verification."""
        sample_bytes = b"CloudSecurity Hash Test Document"
        hash_digest = compute_sha256(sample_bytes)

        self.assertEqual(len(hash_digest), 64)
        self.assertTrue(verify_sha256(sample_bytes, hash_digest))

        # Tampered content must fail verification
        tampered_bytes = b"CloudSecurity Hash Test Document Modified!"
        self.assertFalse(verify_sha256(tampered_bytes, hash_digest))

    def test_05_flask_system_status(self):
        """Test that the system status endpoint reports healthy configuration."""
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertEqual(json_data["status"], "online")
        self.assertTrue(json_data["encryption_key_configured"])

    def test_06_flask_file_upload_and_download(self):
        """Test end-to-end file upload, encryption, download, and decryption via Flask API."""
        test_content = b"Final Year IT Project - Sample PDF content"
        test_filename = "project_report.pdf"

        # 1. Upload
        data = {
            "file": (io.BytesIO(test_content), test_filename)
        }
        upload_res = self.client.post(
            "/api/upload",
            data=data,
            headers={"X-CSRFToken": self.csrf_token},
            content_type="multipart/form-data"
        )
        self.assertEqual(upload_res.status_code, 201)
        upload_json = upload_res.get_json()
        file_record = upload_json["file"]
        file_id = file_record["id"]

        # 2. Verify integrity via API
        verify_res = self.client.get(f"/api/verify/{file_id}")
        self.assertEqual(verify_res.status_code, 200)
        verify_json = verify_res.get_json()
        self.assertTrue(verify_json["integrity_matched"])
        self.assertEqual(verify_json["status"], "PASS")

        # 3. Download and verify binary content matches
        download_res = self.client.get(f"/api/download/{file_id}")
        self.assertEqual(download_res.status_code, 200)
        self.assertEqual(download_res.data, test_content)

        # 4. Clean up
        del_res = self.client.delete(
            f"/api/delete/{file_id}",
            headers={"X-CSRFToken": self.csrf_token}
        )
        self.assertEqual(del_res.status_code, 200)

    def test_07_disallowed_file_extension(self):
        """Test that executable files are rejected."""
        malicious_content = b"echo 'malicious payload'"
        data = {
            "file": (io.BytesIO(malicious_content), "exploit.exe")
        }
        res = self.client.post(
            "/api/upload",
            data=data,
            headers={"X-CSRFToken": self.csrf_token},
            content_type="multipart/form-data"
        )
        self.assertEqual(res.status_code, 400)
        json_data = res.get_json()
        self.assertIn("not allowed", json_data["error"])

    def test_08_empty_file_rejected(self):
        """Test that empty (0 bytes) files are rejected."""
        data = {
            "file": (io.BytesIO(b""), "empty.txt")
        }
        res = self.client.post(
            "/api/upload",
            data=data,
            headers={"X-CSRFToken": self.csrf_token},
            content_type="multipart/form-data"
        )
        self.assertEqual(res.status_code, 400)
        json_data = res.get_json()
        self.assertIn("empty", json_data["error"])


if __name__ == "__main__":
    unittest.main()
