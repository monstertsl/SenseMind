"""系统配置路由"""

import re
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from typing import Optional

from ..core.database import get_db
from ..core.auth import require_role, get_current_user, AuthContext
from ..core.audit import write_system_log
from ..db_models.system_config import SystemConfig
from ..schemas import ApiResponse

router = APIRouter(prefix="/api/v1/system-config", tags=["系统配置"])


class SystemConfigUpdate(BaseModel):
    ai_retention_days: Optional[int] = None
    raw_log_retention_days: Optional[int] = None
    audit_log_retention_days: Optional[int] = None
    login_fail_limit: Optional[int] = None
    inactive_days_limit: Optional[int] = None
    idle_timeout_minutes: Optional[int] = None
    allowed_login_ips: Optional[str] = None
    ntp_servers: Optional[str] = None


# 安全策略字段 → 存储优化字段
_SECURITY_FIELDS = {"login_fail_limit", "inactive_days_limit",
                    "idle_timeout_minutes", "allowed_login_ips"}
_STORAGE_FIELDS = {"ai_retention_days", "raw_log_retention_days",
                   "audit_log_retention_days"}
_NTP_FIELDS = {"ntp_servers"}


def _validate_ntp_servers(value: str) -> str:
    """校验 NTP 服务器列表：逗号分隔，每项为 主机名或IP，可选 :端口。

    空字符串=清空配置（允许）。校验失败抛 400。
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    if "\r" in raw or "\n" in raw:
        raise HTTPException(status_code=400, detail="NTP 服务器配置不能包含换行符")
    entry_re = re.compile(
        r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d{1,5})?$"
    )
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            raise HTTPException(status_code=400, detail="NTP 服务器配置存在空项，请检查逗号分隔格式")
        match = entry_re.match(entry)
        if not match:
            raise HTTPException(
                status_code=400,
                detail=f"NTP 服务器格式无效：{entry}（应为 主机名或IP[:端口]，如 ntp.aliyun.com 或 192.168.1.10）",
            )
        port_part = match.group(2)
        if port_part and not (1 <= int(port_part[1:]) <= 65535):
            raise HTTPException(
                status_code=400,
                detail=f"NTP 服务器端口无效：{entry}（端口范围 1-65535）",
            )
        # 点分全数字形式必须按 IPv4 严格校验（4 段、每段 0-255），拦住 11111.111.1111.111 这类
        host_part = entry[: -len(port_part)] if port_part else entry
        if "." in host_part and host_part.replace(".", "").isdigit():
            parts = host_part.split(".")
            if len(parts) != 4 or any(not p.isdigit() or int(p) > 255 for p in parts):
                raise HTTPException(
                    status_code=400,
                    detail=f"IP 地址无效：{host_part}（需为 IPv4 格式，4 段、每段 0-255）",
                )
    return ",".join(e.strip() for e in raw.split(",") if e.strip())


def _get_or_create_config(db: Session) -> SystemConfig:
    cfg = db.execute(select(SystemConfig).where(SystemConfig.id == 1)).scalar_one_or_none()
    if not cfg:
        cfg = SystemConfig(id=1)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _cfg_to_dict(cfg: SystemConfig) -> dict:
    return {
        "ai_retention_days": cfg.ai_retention_days,
        "raw_log_retention_days": cfg.raw_log_retention_days,
        "audit_log_retention_days": cfg.audit_log_retention_days,
        "login_fail_limit": cfg.login_fail_limit,
        "inactive_days_limit": cfg.inactive_days_limit,
        "idle_timeout_minutes": cfg.idle_timeout_minutes,
        "allowed_login_ips": cfg.allowed_login_ips or "",
        "ntp_servers": cfg.ntp_servers or "",
        "updated_at": cfg.updated_at.isoformat() + 'Z' if cfg.updated_at else None,
    }


@router.get("")
def get_config(db: Session = Depends(get_db), current_user: AuthContext = Depends(require_role("admin"))):
    cfg = _get_or_create_config(db)
    return ApiResponse(code=0, message="ok", data=_cfg_to_dict(cfg), request_id=str(uuid.uuid4()))


@router.patch("")
def update_config(body: SystemConfigUpdate, request: Request,
                  db: Session = Depends(get_db),
                  current_user: AuthContext = Depends(require_role("admin"))):
    cfg = _get_or_create_config(db)
    changed = body.model_dump(exclude_unset=True)
    # NTP 配置先做格式校验（空字符串=清空，允许）
    if changed.get("ntp_servers") is not None:
        changed["ntp_servers"] = _validate_ntp_servers(changed["ntp_servers"])
    for field, value in changed.items():
        if value is not None:
            setattr(cfg, field, value)
    db.commit()
    db.refresh(cfg)

    # 记录系统日志：安全策略 / 存储优化（LLM 配置不记录）
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or request.headers.get("x-real-ip", "")
        or (request.client.host if request.client else "")
    )
    changed_fields = set(changed.keys())
    if changed_fields & _SECURITY_FIELDS:
        detail_fields = {f: changed[f] for f in changed_fields & _SECURITY_FIELDS if changed[f] is not None}
        write_system_log(db, action="update_security_policy", target_type="system_config",
                         detail=f"修改安全策略: {detail_fields}",
                         operator=current_user.username, ip_address=client_ip)
    if changed_fields & _STORAGE_FIELDS:
        detail_fields = {f: changed[f] for f in changed_fields & _STORAGE_FIELDS if changed[f] is not None}
        write_system_log(db, action="update_storage_policy", target_type="system_config",
                         detail=f"修改存储优化: {detail_fields}",
                         operator=current_user.username, ip_address=client_ip)
    if changed_fields & _NTP_FIELDS:
        detail_fields = {f: changed[f] for f in changed_fields & _NTP_FIELDS if changed[f] is not None}
        write_system_log(db, action="update_ntp_config", target_type="system_config",
                         detail=f"修改 NTP 设置: {detail_fields}",
                         operator=current_user.username, ip_address=client_ip)

    return ApiResponse(code=0, message="ok", data=_cfg_to_dict(cfg), request_id=str(uuid.uuid4()))
