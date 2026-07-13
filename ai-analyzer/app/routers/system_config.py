"""系统配置路由"""

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
    es_retention_days: Optional[int] = None
    raw_log_retention_days: Optional[int] = None
    audit_log_retention_days: Optional[int] = None
    login_fail_limit: Optional[int] = None
    inactive_days_limit: Optional[int] = None
    idle_timeout_minutes: Optional[int] = None
    allowed_login_ips: Optional[str] = None


# 安全策略字段 → 存储优化字段
_SECURITY_FIELDS = {"login_fail_limit", "inactive_days_limit",
                    "idle_timeout_minutes", "allowed_login_ips"}
_STORAGE_FIELDS = {"es_retention_days", "raw_log_retention_days",
                   "audit_log_retention_days"}


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
        "es_retention_days": cfg.es_retention_days,
        "raw_log_retention_days": cfg.raw_log_retention_days,
        "audit_log_retention_days": cfg.audit_log_retention_days,
        "login_fail_limit": cfg.login_fail_limit,
        "inactive_days_limit": cfg.inactive_days_limit,
        "idle_timeout_minutes": cfg.idle_timeout_minutes,
        "allowed_login_ips": cfg.allowed_login_ips or "",
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

    return ApiResponse(code=0, message="ok", data=_cfg_to_dict(cfg), request_id=str(uuid.uuid4()))
