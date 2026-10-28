"""脱敏日志。

脚本禁止直接 print / 使用自带输出：日志必须带 driver 上下文，且凭据字段不得落日志。
"""

import logging

SECRET_HINTS = ("password", "passwd", "token", "secret", "key", "credential")
MASK = "***"


def logger(driver: str) -> logging.Logger:
    return logging.getLogger(f"sensemind_device.{driver}")


def mask(value) -> str:
    return MASK if value not in (None, "") else ""


def mask_config(cfg: dict) -> dict:
    """按字段名猜测敏感项并遮蔽；仅供日志使用，不要用于业务逻辑。"""
    masked = {}
    for key, value in (cfg or {}).items():
        lowered = str(key).lower()
        if any(hint in lowered for hint in SECRET_HINTS):
            masked[key] = mask(value)
        else:
            masked[key] = value
    return masked
