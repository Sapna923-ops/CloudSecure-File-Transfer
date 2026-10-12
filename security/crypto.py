"""
=============================================================================
CloudSecure File Transfer - Cryptographic Security Module
=============================================================================
Provides authenticated symmetric encryption using Python's cryptography library.

Under the hood:
- Fernet uses AES (Advanced Encryption Standard) with a 128-bit key in CBC mode.
- It uses PKCS7 padding for data alignment.
- It calculates an HMAC using SHA-256 for authentication and integrity checking.
- It prevents ciphertext tampering: any modification of the ciphertext causes
  decryption to fail immediately.
=============================================================================
"""

import logging
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


class DecryptionError(Exception):
    """Raised when file decryption fails (wrong key or tampered data)."""
    pass


class InvalidKeyError(Exception):
    """Raised when the provided encryption key is malformed or missing."""
    pass


def is_valid_key(key: str) -> bool:
    """
    Validates whether a string is a valid 32-byte url-safe base64-encoded Fernet key.
    """
    if not key or not isinstance(key, str):
        return False
    try:
        Fernet(key.encode("utf-8"))
        return True
    except Exception:
        return False


def encrypt_bytes(data: bytes, key: str) -> bytes:
    """
    Encrypts raw bytes using the provided Fernet key.

    Parameters:
        data (bytes): The original unencrypted file content.
        key (str): The secret base64-encoded Fernet key.

    Returns:
        bytes: The encrypted ciphertext.
    """
    if not is_valid_key(key):
        logger.error("Encryption failed: Invalid or missing secret key.")
        raise InvalidKeyError("A valid 32-byte Fernet encryption key is required.")

    if not isinstance(data, bytes):
        raise TypeError("Data to encrypt must be in raw bytes format.")

    fernet = Fernet(key.encode("utf-8"))
    encrypted_data = fernet.encrypt(data)
    return encrypted_data


def decrypt_bytes(ciphertext: bytes, key: str) -> bytes:
    """
    Decrypts encrypted ciphertext using the provided Fernet key.

    Parameters:
        ciphertext (bytes): The encrypted file content stored on disk.
        key (str): The secret base64-encoded Fernet key.

    Returns:
        bytes: The recovered original unencrypted file content.
    """
    if not is_valid_key(key):
        logger.error("Decryption failed: Invalid or missing secret key.")
        raise InvalidKeyError("A valid 32-byte Fernet encryption key is required.")

    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext to decrypt must be in raw bytes format.")

    try:
        fernet = Fernet(key.encode("utf-8"))
        decrypted_data = fernet.decrypt(ciphertext)
        return decrypted_data
    except InvalidToken:
        logger.error("Decryption failed: Invalid token. Data was modified or key is incorrect.")
        raise DecryptionError("Decryption failed. The key is incorrect or the file was tampered with.")
    except Exception as exc:
        logger.error("Decryption encountered an unexpected error.")
        raise DecryptionError(f"Unexpected decryption error: {str(exc)}")
