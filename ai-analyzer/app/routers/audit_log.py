"""审计日志路由：系统日志查询/清理（含登录记录）"""

import uuid
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, delete, and_, func, or_
from sqlalchemy.orm import Session
from typing import Optional

from ..core.database import get_db
from ..core.auth import require_role, AuthContext
from ..core.audit import write_system_log
from ..db_models.audit_log import SystemLog
from ..schemas import ApiResponse

router = APIRouter(prefix="/api/v1/audit-logs", tags=["审计日志"])


class CleanupRequest(BaseModel):
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


@router.get("/system")
def list_system_logs(
    action: Optional[str] = None,
    target_type: Optional[str] = None,
    operator: Optional[str] = None,
    detail: Optional[str] = None,
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
    if detail:
        conditions.append(SystemLog.detail.ilike(f"%{detail}%"))
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
        "created_at": l.created_at.isoformat() + 'Z' if l.created_at else None,
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
    deleted = db.execute(
        delete(SystemLog).where(
            SystemLog.created_at < cutoff,
            SystemLog.action != "cleanup_audit_log",
        )
    ).rowcount or 0
    db.commit()
    write_system_log(db, action="cleanup_audit_log", target_type="audit_log",
                     detail=f"手动清理 {body.days} 天前系统日志 {deleted} 条",
                     operator=current_user.username, ip_address="")
    return ApiResponse(code=0, message="ok", data={
        "deleted_count": deleted, "message": f"已删除 {deleted} 条系统日志",
    }, request_id=str(uuid.uuid4()))
