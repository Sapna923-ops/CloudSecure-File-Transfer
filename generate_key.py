"""
=============================================================================
CloudSecure File Transfer - Cryptographic Key Generator
=============================================================================
This utility creates a cryptographically secure 256-bit encryption key
using the Fernet specification (AES in CBC mode with HMAC-SHA256 authentication).

It securely stores the key in your local .env file.
=============================================================================
"""

import os
import secrets
from cryptography.fernet import Fernet

ENV_FILE = os.path.join(os.path.dirname(__file__), ".env")
ENV_EXAMPLE = os.path.join(os.path.dirname(__file__), ".env.example")


def generate_and_save_key():
    print("=" * 60)
    print("  CloudSecure Key Generation Utility")
    print("=" * 60)

    # 1. Generate a new cryptographically secure Fernet key
    new_encryption_key = Fernet.generate_key().decode("utf-8")
    new_flask_secret = secrets.token_hex(24)

    # 2. Check if .env file exists
    if not os.path.exists(ENV_FILE):
        if os.path.exists(ENV_EXAMPLE):
            with open(ENV_EXAMPLE, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = (
                "FLASK_SECRET_KEY=replace-me\n"
                "STORAGE_MODE=local\n"
                "SECRET_ENCRYPTION_KEY=\n"
                "MAX_UPLOAD_SIZE_MB=16\n"
            )

        # Replace placeholders with new keys
        content = content.replace("SECRET_ENCRYPTION_KEY=", f"SECRET_ENCRYPTION_KEY={new_encryption_key}")
        content = content.replace(
            "FLASK_SECRET_KEY=change-this-in-production-to-a-random-secret-key",
            f"FLASK_SECRET_KEY={new_flask_secret}"
        )

        with open(ENV_FILE, "w", encoding="utf-8") as f:
            f.write(content)

        print("[SUCCESS] Created new .env file with generated keys.")
    else:
        # Read existing .env
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        has_enc_key = False
        new_lines = []
        for line in lines:
            if line.startswith("SECRET_ENCRYPTION_KEY="):
                has_enc_key = True
                current_val = line.strip().split("=", 1)[1]
                if not current_val:
                    new_lines.append(f"SECRET_ENCRYPTION_KEY={new_encryption_key}\n")
                    print("[INFO] Populated empty SECRET_ENCRYPTION_KEY in .env.")
                else:
                    print("[WARNING] SECRET_ENCRYPTION_KEY already exists in .env.")
                    print("To prevent data loss (inability to decrypt past files), it was NOT overwritten.")
                    return
            else:
                new_lines.append(line)

        if not has_enc_key:
            new_lines.append(f"\nSECRET_ENCRYPTION_KEY={new_encryption_key}\n")
            print("[INFO] Appended SECRET_ENCRYPTION_KEY to .env.")

        with open(ENV_FILE, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    print("\n[KEY GENERATED SUCCESSFULLY]")
    print(f"Key preview: {new_encryption_key[:6]}...{new_encryption_key[-6:]} (Hidden for security)")
    print("-" * 60)
    print("SECURITY & BACKUP NOTICE:")
    print("1. Your key is stored ONLY in your local '.env' file.")
    print("2. The '.gitignore' file ensures it is NEVER pushed to GitHub.")
    print("3. BACKUP ADVICE: Save this key in a secure offline location (e.g. password manager).")
    print("   If you lose this key, any encrypted files CANNOT be recovered!")
    print("=" * 60)


if __name__ == "__main__":
    generate_and_save_key()
