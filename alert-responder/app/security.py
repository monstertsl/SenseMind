"""Encryption helpers for sensitive responder settings."""

import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def _get_fernet() -> Fernet:
    key_material = os.environ.get("ENCRYPT_KEY", "")
    if not key_material:
        raise RuntimeError("ENCRYPT_KEY is not configured")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"sensemind-salt-v1",
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(key_material.encode()))
    return Fernet(key)


def encrypt_data(data: str) -> str:
    if not data:
        return ""
    return _get_fernet().encrypt(data.encode()).decode()


def decrypt_data(data: str) -> str:
    if not data:
        return ""
    return _get_fernet().decrypt(data.encode()).decode()