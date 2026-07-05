"""审计日志路由：登录日志 + 系统日志 查询/清理"""

import uuid
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, delete, and_, func
from sqlalchemy.orm import Session
from typing import Optional

from ..core.database import get_db
from ..core.auth import require_role, AuthContext
from ..core.audit import write_system_log
from ..db_models.audit_log import LoginLog, SystemLog
from ..schemas import ApiResponse

router = APIRouter(prefix="/api/v1/audit-logs", tags=["审计日志"])


class CleanupRequest(BaseModel):
    type: str  # login / system
    days: int


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        try:
            return datetime.strptime(s, "%Y-%m-%d")
        except Exception:
            return None


@router.get("/login")
def list_login_logs(
    username: Optional[str] = None,
    success: Optional[bool] = None,
    ip_address: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: AuthContext = Depends(require_role("admin")),
):
    conditions = []
    if username:
        conditions.append(LoginLog.username == username)
    if success is not None:
        conditions.append(LoginLog.success == success)
    if ip_address:
        conditions.append(LoginLog.ip_address == ip_address)
    sd, ed = _parse_dt(start_date), _parse_dt(end_date)
    if sd:
        conditions.append(LoginLog.created_at >= sd)
    if ed:
        conditions.append(LoginLog.created_at <= ed)

    count_q = select(func.count()).select_from(LoginLog)
    if conditions:
        count_q = count_q.where(and_(*conditions))
    total = db.execute(count_q).scalar() or 0

    q = select(LoginLog).order_by(LoginLog.created_at.desc())
    if conditions:
        q = q.where(and_(*conditions))
    q = q.offset((page - 1) * page_size).limit(page_size)
    logs = db.execute(q).scalars().all()

    items = [{
        "id": l.id, "username": l.username, "success": l.success,
        "ip_address": l.ip_address, "user_agent": l.user_agent,
        "message": l.message,
        "created_at": l.created_at.isoformat() if l.created_at else None,
    } for l in logs]

    return ApiResponse(code=0, message="ok", data={
        "total": total, "page": page, "page_size": page_size, "items": items,
    }, request_id=str(uuid.uuid4()))


@router.get("/system")
def list_system_logs(
    action: Optional[str] = None,
    target_type: Optional[str] = None,
    operator: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: AuthContext = Depends(require_role("admin")),
):
    conditions = []
    if action:
        conditions.append(SystemLog.action == action)
    if target_type:
        conditions.append(SystemLog.target_type == target_type)
    if operator:
        conditions.append(SystemLog.operator == operator)
    sd, ed = _parse_dt(start_date), _parse_dt(end_date)
    if sd:
        conditions.append(SystemLog.created_at >= sd)
    if ed:
        conditions.append(SystemLog.created_at <= ed)

    count_q = select(func.count()).select_from(SystemLog)
    if conditions:
        count_q = count_q.where(and_(*conditions))
    total = db.execute(count_q).scalar() or 0

    q = select(SystemLog).order_by(SystemLog.created_at.desc())
    if conditions:
        q = q.where(and_(*conditions))
    q = q.offset((page - 1) * page_size).limit(page_size)
    logs = db.execute(q).scalars().all()

    items = [{
        "id": l.id, "action": l.action, "target_type": l.target_type,
        "target_id": l.target_id, "detail": l.detail,
        "operator": l.operator, "ip_address": l.ip_address,
        "created_at": l.created_at.isoformat() if l.created_at else None,
    } for l in logs]

    return ApiResponse(code=0, message="ok", data={
        "total": total, "page": page, "page_size": page_size, "items": items,
    }, request_id=str(uuid.uuid4()))


@router.post("/cleanup")
def cleanup_logs(body: CleanupRequest, db: Session = Depends(get_db),
                 current_user: AuthContext = Depends(require_role("admin"))):
    if body.days <= 0:
        raise HTTPException(status_code=400, detail="天数必须大于 0")
    cutoff = datetime.utcnow() - timedelta(days=body.days)
    deleted = 0
    if body.type == "login":
        result = db.execute(delete(LoginLog).where(LoginLog.created_at < cutoff))
        deleted = result.rowcount or 0
    elif body.type == "system":
        result = db.execute(delete(SystemLog).where(SystemLog.created_at < cutoff))
        deleted = result.rowcount or 0
    else:
        raise HTTPException(status_code=400, detail="类型必须为 login 或 system")
    db.commit()
    write_system_log(db, action="cleanup_audit_log", target_type="audit_log",
                     detail=f"清理 {body.type} 日志 {deleted} 条（{body.days} 天前）",
                     operator=current_user.username, ip_address="")
    return ApiResponse(code=0, message="ok", data={
        "deleted_count": deleted, "message": f"已删除 {deleted} 条 {body.type} 日志",
    }, request_id=str(uuid.uuid4()))
