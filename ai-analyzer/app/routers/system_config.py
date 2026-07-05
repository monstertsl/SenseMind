"""系统配置路由"""

import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from typing import Optional

from ..core.database import get_db
from ..core.auth import require_role, get_current_user, AuthContext
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
        "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
    }


@router.get("")
def get_config(db: Session = Depends(get_db), current_user: AuthContext = Depends(get_current_user)):
    cfg = _get_or_create_config(db)
    return ApiResponse(code=0, message="ok", data=_cfg_to_dict(cfg), request_id=str(uuid.uuid4()))


@router.patch("")
def update_config(body: SystemConfigUpdate, db: Session = Depends(get_db),
                  current_user: AuthContext = Depends(require_role("admin"))):
    cfg = _get_or_create_config(db)
    for field, value in body.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(cfg, field, value)
    db.commit()
    db.refresh(cfg)
    return ApiResponse(code=0, message="ok", data=_cfg_to_dict(cfg), request_id=str(uuid.uuid4()))
