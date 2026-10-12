"""
=============================================================================
CloudSecure File Transfer - SHA-256 Integrity Verification Module
=============================================================================
Computes and verifies cryptographic SHA-256 checksums to ensure file integrity.

Why this matters in Cloud Computing:
- Storage in the cloud or across networks is susceptible to bit flips,
  incomplete transfers, or malicious tampering.
- By calculating a SHA-256 hash before encryption and verifying it after
  decryption, we provide mathematical proof that the downloaded file is
  100% identical to the file originally uploaded.
=============================================================================
"""

import hashlib
import hmac


def compute_sha256(data: bytes) -> str:
    """
    Computes the SHA-256 cryptographic digest of a byte sequence.

    Parameters:
        data (bytes): Raw bytes to hash.

    Returns:
        str: 64-character lowercase hexadecimal hash string.
    """
    if not isinstance(data, bytes):
        raise TypeError("Data for SHA-256 computation must be raw bytes.")

    sha256_hasher = hashlib.sha256()
    sha256_hasher.update(data)
    return sha256_hasher.hexdigest()


def verify_sha256(data: bytes, expected_hash: str) -> bool:
    """
    Verifies data against an expected SHA-256 hash using constant-time comparison.
    Constant-time comparison (hmac.compare_digest) protects against timing attacks.

    Parameters:
        data (bytes): Raw bytes to verify.
        expected_hash (str): The expected 64-character hexadecimal hash.

    Returns:
        bool: True if the calculated hash strictly matches the expected hash.
    """
    if not expected_hash or not isinstance(expected_hash, str):
        return False

    actual_hash = compute_sha256(data)
    return hmac.compare_digest(actual_hash.lower(), expected_hash.lower())
