"""设备表单加密工具：国产设备常见「AES-CBC + 零填充 + base64」的登录口令加密。

放在公共模块里，避免每个设备脚本各自实现一份（也避免脚本直接依赖 cryptography）。
"""

import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16


def aes_cbc_zero_base64(text: str, key: str, iv: str) -> str:
    """AES-CBC 加密并输出标准 base64。

    - key 长度必须是 16/24/32 字节，iv 必须是 16 字节（按 UTF-8 取字节）
    - 明文按 0x00 补齐到 16 字节的整数倍（已经是整数倍时不补），即 zero padding
    """
    key_bytes = key.encode("utf-8")
    iv_bytes = iv.encode("utf-8")
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("AES 密钥长度必须是 16/24/32 字节")
    if len(iv_bytes) != BLOCK_SIZE:
        raise ValueError("AES IV 长度必须是 16 字节")

    raw = text.encode("utf-8")
    padded = raw + b"\x00" * ((-len(raw)) % BLOCK_SIZE)
    if not padded:
        padded = b"\x00" * BLOCK_SIZE

    encryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("ascii")
