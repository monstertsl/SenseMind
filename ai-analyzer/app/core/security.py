"""对称加密工具 —— 用于 TOTP 密钥等敏感字段加密存储"""

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def _get_fernet() -> Fernet:
    import os
    key_material = os.environ.get("ENCRYPT_KEY", "")
    if not key_material:
        raise RuntimeError("ENCRYPT_KEY 环境变量未配置，无法加解密敏感字段")
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
