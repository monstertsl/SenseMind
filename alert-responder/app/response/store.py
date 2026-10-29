"""设备配置的校验、加密与运行时组装。

设备字段由脚本清单声明，平台不解释语义：这里只做「按清单校验 → 敏感项加密 → 运行时解密下发」。
"""

import logging

from fastapi import HTTPException

from ..security import decrypt_data, encrypt_data
from . import registry

logger = logging.getLogger(__name__)

SECRET_PREFIX = "enc:"
PLATFORM_DEFAULTS = {
    "timeout_seconds": 10,
    "verify_tls": False,
    "ca_cert_pem": "",
    "max_concurrency": 4,
}


def _coerce(field: dict, raw):
    field_type = field["type"]
    label = field.get("label") or field["name"]
    if field_type == "int":
        try:
            return int(raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f"{label} 必须是整数") from None
    if field_type == "bool":
        if isinstance(raw, bool):
            return raw
        return str(raw).lower() in ("1", "true", "yes", "on")
    if field_type == "select":
        choices = field.get("choices") or []
        if choices and raw not in choices:
            raise HTTPException(status_code=400, detail=f"{label} 取值不在可选范围内")
        return raw
    return str(raw)


def validate_config(spec: registry.DriverSpec, payload: dict, *, existing: dict = None) -> dict:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="设备配置必须是对象")
    existing = existing or {}
    allowed = {item["name"] for item in spec.config_schema} | set(registry.RESERVED_FIELD_NAMES)
    unknown = set(payload) - allowed
    if unknown:
        raise HTTPException(status_code=400, detail=f"未知配置项：{', '.join(sorted(unknown))}")

    values = {}
    for field in spec.config_schema:
        name = field["name"]
        raw = payload.get(name)
        if isinstance(raw, str):
            raw = raw.strip()
        if raw in (None, ""):
            # 敏感字段留空表示沿用已保存的值；非敏感字段留空即视为未填写
            if field.get("required") and not (field.get("secret") and existing.get(name)):
                raise HTTPException(status_code=400, detail=f"缺少必填项：{field.get('label') or name}")
            continue
        values[name] = _coerce(field, raw)

    for name in registry.RESERVED_FIELD_NAMES & set(payload):
        raw = payload[name]
        if isinstance(raw, str):
            raw = raw.strip()
        if raw in (None, ""):
            continue
        if name in ("timeout_seconds", "max_concurrency"):
            try:
                values[name] = int(raw)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{name} 必须是整数") from None
        elif name == "verify_tls":
            values[name] = bool(raw) if isinstance(raw, bool) else str(raw).lower() in ("1", "true", "yes", "on")
        else:
            values[name] = raw
    return values


def seal_config(spec: registry.DriverSpec, values: dict, *, existing: dict = None) -> tuple:
    """敏感字段加密为 enc: 前缀；留空且已有旧值则原样保留。"""
    existing = existing or {}
    config = {}
    for name, value in values.items():
        config[name] = value
    for name in spec.secret_fields:
        raw = values.get(name)
        if raw is None:
            if existing.get(name):
                config[name] = existing[name]
            continue
        try:
            config[name] = SECRET_PREFIX + encrypt_data(str(raw))
        except RuntimeError:
            raise HTTPException(status_code=503, detail="服务器未配置凭据加密密钥") from None
    secret_fields = [name for name in spec.secret_fields if config.get(name)]
    return config, secret_fields


def runtime_config(device) -> dict:
    """解密后交给脚本的 cfg：包含脚本声明字段与平台字段。"""
    cfg = {}
    for name, value in (device.config or {}).items():
        if isinstance(value, str) and value.startswith(SECRET_PREFIX):
            try:
                cfg[name] = decrypt_data(value[len(SECRET_PREFIX):])
            except Exception:
                logger.error("设备 %s 的字段 %s 解密失败，请检查 ENCRYPT_KEY", device.id, name)
                raise HTTPException(status_code=500, detail="设备凭据无法解密，请重新保存设备配置") from None
        else:
            cfg[name] = value
    for name, default in PLATFORM_DEFAULTS.items():
        cfg.setdefault(name, default)
    return cfg


def public_config(device) -> dict:
    """读接口：敏感字段只回是否已配置。"""
    config = dict(device.config or {})
    secret_fields = set(device.secret_fields or [])
    configured = {}
    for name in secret_fields:
        configured[name] = bool(config.get(name))
        config.pop(name, None)
    return {"config": config, "secret_configured": configured}


def device_view(device, spec=None) -> dict:
    payload = {
        "id": device.id,
        "name": device.name,
        "driver": device.driver,
        "display_name": spec.display_name if spec else device.driver,
        "schema_version": device.schema_version,
        "enabled": device.enabled,
        "created_at": device.created_at.isoformat() if device.created_at else None,
        "updated_at": device.updated_at.isoformat() if device.updated_at else None,
    }
    payload.update(public_config(device))
    return payload
