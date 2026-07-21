"""AI 分析白名单路由"""

import re
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select, func, or_
from sqlalchemy.orm import Session
from typing import Optional

from ..core.database import get_db
from ..core.auth import require_role, AuthContext
from ..core.audit import write_system_log
from ..db_models.ai_bypass_rule import AiBypassRule
from ..schemas import ApiResponse

router = APIRouter(prefix="/api/v1/ai-bypass-rules", tags=["AI分析白名单"])

_IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

# 域名标签：每段 [a-z0-9] 开头结尾，中间可含 -；TLD 至少 2 个字母
_HOST_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')


def _normalize_host(raw: str) -> str:
    """规范化用户输入的 host：去通配前缀、scheme、路径、端口、末尾点，转小写"""
    h = (raw or "").strip().lower()
    if h.startswith("*."):
        h = h[2:]
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]      # 去路径/查询
    h = h.split(":", 1)[0]      # 去端口
    h = h.rstrip(".")
    return h


def _validate_host(host: str) -> bool:
    """校验 host 字段，空表示通配。支持裸域名或用户误粘贴的 URL/端口形式"""
    if not host:
        return True
    h = _normalize_host(host)
    if not h:
        return False
    return bool(_HOST_RE.match(h))


class BypassRuleCreate(BaseModel):
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    host: str = ""
    remark: str = ""


class BypassRuleUpdate(BaseModel):
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    host: Optional[str] = None
    remark: Optional[str] = None


def _validate_ip(ip: str) -> bool:
    """校验 IPv4 格式，不支持 CIDR（如 10.10.168.0/24）"""
    if not ip:
        return True  # 空表示通配
    if '/' in ip:
        return False
    m = _IPV4_RE.match(ip)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def _validate_port(port: int) -> bool:
    """校验端口范围 1-65535，0 表示通配"""
    return port == 0 or 1 <= port <= 65535


def _client_ip(request: Request) -> str:
    return (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or request.headers.get("x-real-ip", "")
        or (request.client.host if request.client else "")
    )


def _rule_to_dict(rule: AiBypassRule) -> dict:
    return {
        "id": rule.id,
        "src_ip": rule.src_ip or "",
        "src_port": rule.src_port or 0,
        "dst_ip": rule.dst_ip or "",
        "dst_port": rule.dst_port or 0,
        "host": rule.host or "",
        "remark": rule.remark or "",
        "created_at": rule.created_at.isoformat() + 'Z' if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() + 'Z' if rule.updated_at else None,
    }


def _format_rule(rule: AiBypassRule) -> str:
    parts = []
    parts.append(f"{rule.src_ip or '*'}:{rule.src_port or '*'} -> {rule.dst_ip or '*'}:{rule.dst_port or '*'}")
    if rule.host:
        parts.append(f"host={rule.host}")
    return " ".join(parts)


@router.get("")
def list_rules(
    keyword: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: AuthContext = Depends(require_role("admin")),
):
    conditions = []
    if keyword:
        kw = f"%{keyword}%"
        conditions.append(or_(
            AiBypassRule.src_ip.ilike(kw),
            AiBypassRule.dst_ip.ilike(kw),
            AiBypassRule.host.ilike(kw),
            AiBypassRule.remark.ilike(kw),
        ))

    count_q = select(func.count()).select_from(AiBypassRule)
    if conditions:
        count_q = count_q.where(*conditions)
    total = db.execute(count_q).scalar() or 0

    q = select(AiBypassRule).order_by(AiBypassRule.created_at.desc())
    if conditions:
        q = q.where(*conditions)
    q = q.offset((page - 1) * page_size).limit(page_size)
    rules = db.execute(q).scalars().all()

    return ApiResponse(code=0, message="ok", data={
        "total": total, "page": page, "page_size": page_size,
        "items": [_rule_to_dict(r) for r in rules],
    }, request_id=str(uuid.uuid4()))


@router.post("")
def create_rule(body: BypassRuleCreate, request: Request, db: Session = Depends(get_db),
                current_user: AuthContext = Depends(require_role("admin"))):
    # 全空校验
    if not body.src_ip and not body.src_port and not body.dst_ip and not body.dst_port and not body.host:
        raise HTTPException(status_code=400, detail="至少填写一个四元组字段或 Host")
    # IP 格式校验
    if body.src_ip and not _validate_ip(body.src_ip):
        raise HTTPException(status_code=400, detail=f"源 IP 格式错误: {body.src_ip}（不支持 CIDR）")
    if body.dst_ip and not _validate_ip(body.dst_ip):
        raise HTTPException(status_code=400, detail=f"目的 IP 格式错误: {body.dst_ip}（不支持 CIDR）")
    # 端口范围校验
    if not _validate_port(body.src_port):
        raise HTTPException(status_code=400, detail=f"源端口范围错误: {body.src_port}（1-65535）")
    if not _validate_port(body.dst_port):
        raise HTTPException(status_code=400, detail=f"目的端口范围错误: {body.dst_port}（1-65535）")
    # Host 格式校验
    if body.host and not _validate_host(body.host):
        raise HTTPException(status_code=400, detail=f"Host 格式错误: {body.host}（应为域名，如 example.com）")

    rule = AiBypassRule(
        src_ip=body.src_ip.strip(),
        src_port=body.src_port,
        dst_ip=body.dst_ip.strip(),
        dst_port=body.dst_port,
        host=_normalize_host(body.host),
        remark=body.remark.strip(),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    write_system_log(db, action="create_bypass_rule", target_type="ai_bypass_rule",
                     target_id=str(rule.id),
                     detail=f"创建白名单: {_format_rule(rule)} ({rule.remark})",
                     operator=current_user.username, ip_address=_client_ip(request))
    return ApiResponse(code=0, message="ok", data=_rule_to_dict(rule), request_id=str(uuid.uuid4()))


@router.patch("/{rule_id}")
def update_rule(rule_id: int, body: BypassRuleUpdate, request: Request, db: Session = Depends(get_db),
                current_user: AuthContext = Depends(require_role("admin"))):
    rule = db.execute(select(AiBypassRule).where(AiBypassRule.id == rule_id)).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="白名单规则不存在")

    old_desc = _format_rule(rule)
    changes = []
    if body.src_ip is not None:
        if body.src_ip and not _validate_ip(body.src_ip):
            raise HTTPException(status_code=400, detail=f"源 IP 格式错误: {body.src_ip}（不支持 CIDR）")
        rule.src_ip = body.src_ip.strip()
        changes.append("src_ip")
    if body.src_port is not None:
        if not _validate_port(body.src_port):
            raise HTTPException(status_code=400, detail=f"源端口范围错误: {body.src_port}（1-65535）")
        rule.src_port = body.src_port
        changes.append("src_port")
    if body.dst_ip is not None:
        if body.dst_ip and not _validate_ip(body.dst_ip):
            raise HTTPException(status_code=400, detail=f"目的 IP 格式错误: {body.dst_ip}（不支持 CIDR）")
        rule.dst_ip = body.dst_ip.strip()
        changes.append("dst_ip")
    if body.dst_port is not None:
        if not _validate_port(body.dst_port):
            raise HTTPException(status_code=400, detail=f"目的端口范围错误: {body.dst_port}（1-65535）")
        rule.dst_port = body.dst_port
        changes.append("dst_port")
    if body.host is not None:
        if body.host and not _validate_host(body.host):
            raise HTTPException(status_code=400, detail=f"Host 格式错误: {body.host}（应为域名，如 example.com）")
        rule.host = _normalize_host(body.host)
        changes.append("host")
    if body.remark is not None:
        rule.remark = body.remark.strip()
        changes.append("remark")

    # 全空校验（更新后不能全部为空）
    if not rule.src_ip and not rule.src_port and not rule.dst_ip and not rule.dst_port and not rule.host:
        raise HTTPException(status_code=400, detail="至少保留一个四元组字段或 Host")

    db.commit()
    db.refresh(rule)

    write_system_log(db, action="update_bypass_rule", target_type="ai_bypass_rule",
                     target_id=str(rule.id),
                     detail=f"修改白名单: {old_desc} → {_format_rule(rule)}",
                     operator=current_user.username, ip_address=_client_ip(request))
    return ApiResponse(code=0, message="ok", data=_rule_to_dict(rule), request_id=str(uuid.uuid4()))


@router.delete("/{rule_id}")
def delete_rule(rule_id: int, request: Request, db: Session = Depends(get_db),
                current_user: AuthContext = Depends(require_role("admin"))):
    rule = db.execute(select(AiBypassRule).where(AiBypassRule.id == rule_id)).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="白名单规则不存在")
    desc = _format_rule(rule)
    db.delete(rule)
    db.commit()

    write_system_log(db, action="delete_bypass_rule", target_type="ai_bypass_rule",
                     target_id=str(rule_id),
                     detail=f"删除白名单: {desc} ({rule.remark})",
                     operator=current_user.username, ip_address=_client_ip(request))
    return ApiResponse(code=0, message="ok", data={"message": "已删除"}, request_id=str(uuid.uuid4()))
