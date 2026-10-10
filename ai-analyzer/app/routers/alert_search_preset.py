"""分析中心检索快捷方式路由

把分析中心的筛选条件保存为具名快捷方式，支持应用（前端本地）与删除。
存储方式与「系统设置 - AI 分析白名单」一致（PostgreSQL + CRUD + 审计日志），
因为两者都属于「筛选命中」类配置，后续告警联动可直接复用这里的 filters。
"""

import json
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..core.database import get_db
from ..core.auth import get_current_user, AuthContext
from ..core.audit import write_system_log
from ..db_models.alert_search_preset import AlertSearchPreset
from ..schemas import ApiResponse, AlertQueryParams

router = APIRouter(prefix="/api/v1/alert-search-presets", tags=["分析中心检索快捷方式"])

# 允许保存的筛选键：与 AlertQueryParams 的筛选字段同名。
# 后续告警联动可直接用这些键构造 AlertQueryParams 做命中匹配，避免前后端语义漂移。
ALLOWED_FILTER_KEYS = (
    "source_ip", "destination_ip", "soc_name", "threat_verdict",
    "attack_result", "alert_signature", "confidence",
    "confidence_min", "confidence_max", "kql",
    "exclude_source_ip", "exclude_destination_ip", "exclude_alert_signature",
)

_NUMERIC_FILTER_KEYS = {"confidence", "confidence_min", "confidence_max"}


class PresetCreate(BaseModel):
    name: str
    remark: str = ""
    filters: dict[str, Any] = {}


class PresetUpdate(BaseModel):
    name: Optional[str] = None
    remark: Optional[str] = None
    filters: Optional[dict[str, Any]] = None
    is_enabled: Optional[bool] = None


def _normalize_filters(raw: Optional[dict]) -> dict:
    """归一化筛选条件：仅保留允许的键、丢弃空值、数值键转 float"""
    result: dict[str, Any] = {}
    for key, value in (raw or {}).items():
        if key not in ALLOWED_FILTER_KEYS or value is None:
            continue
        if key in _NUMERIC_FILTER_KEYS:
            try:
                result[key] = float(value)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{key} 必须为数字")
        else:
            text = str(value).strip()
            if text:
                result[key] = text
    return result


def _parse_filters(raw: str) -> dict:
    try:
        data = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _preset_to_dict(preset: AlertSearchPreset) -> dict:
    return {
        "id": preset.id,
        "name": preset.name,
        "remark": preset.remark or "",
        "filters": _parse_filters(preset.filters),
        "is_enabled": bool(preset.is_enabled),
        "created_by": preset.created_by or "",
        "created_at": preset.created_at.isoformat() + "Z" if preset.created_at else None,
        "updated_at": preset.updated_at.isoformat() + "Z" if preset.updated_at else None,
    }


def filters_to_params(preset: AlertSearchPreset) -> AlertQueryParams:
    """把快捷方式的筛选条件转为查询参数（供后续告警联动模块复用）"""
    return AlertQueryParams(**_parse_filters(preset.filters))


def _client_ip(request: Request) -> str:
    return (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or request.headers.get("x-real-ip", "")
        or (request.client.host if request.client else "")
    )


def _check_name_conflict(db: Session, name: str, exclude_id: Optional[int] = None) -> None:
    q = select(AlertSearchPreset).where(AlertSearchPreset.name == name)
    if exclude_id is not None:
        q = q.where(AlertSearchPreset.id != exclude_id)
    if db.execute(q).scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"快捷方式名称已存在: {name}")


def _check_filters_conflict(db: Session, filters: dict, exclude_id: Optional[int] = None) -> None:
    """同检索条件只允许存在一条快捷方式

    同条件的多条快捷方式在界面上无法区分，告警联动侧还会重复触发同一动作；
    过滤条件入库时统一 json.dumps(sort_keys=True)，因此可直接按字符串判等。
    """
    target = json.dumps(filters, ensure_ascii=False, sort_keys=True)
    q = select(AlertSearchPreset).where(AlertSearchPreset.filters == target)
    if exclude_id is not None:
        q = q.where(AlertSearchPreset.id != exclude_id)
    existed = db.execute(q).scalars().first()
    if existed:
        raise HTTPException(status_code=400, detail=f"已存在相同检索条件的快捷方式「{existed.name}」")


@router.get("")
def list_presets(
    keyword: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: AuthContext = Depends(get_current_user),
):
    conditions = []
    if keyword:
        kw = f"%{keyword}%"
        conditions.append(AlertSearchPreset.name.ilike(kw))

    count_q = select(func.count()).select_from(AlertSearchPreset)
    q = select(AlertSearchPreset).order_by(AlertSearchPreset.created_at.desc())
    if conditions:
        count_q = count_q.where(*conditions)
        q = q.where(*conditions)
    total = db.execute(count_q).scalar() or 0
    presets = db.execute(q).scalars().all()

    return ApiResponse(code=0, message="ok", data={
        "total": total,
        "items": [_preset_to_dict(p) for p in presets],
    }, request_id=str(uuid.uuid4()))


@router.post("")
def create_preset(body: PresetCreate, db: Session = Depends(get_db),
                  current_user: AuthContext = Depends(get_current_user)):
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="快捷方式名称不能为空")
    if len(name) > 100:
        raise HTTPException(status_code=400, detail="快捷方式名称过长（最多 100 字符）")

    filters = _normalize_filters(body.filters)
    if not filters:
        raise HTTPException(status_code=400, detail="请检索后保存")
    _check_name_conflict(db, name)
    _check_filters_conflict(db, filters)

    preset = AlertSearchPreset(
        name=name,
        remark=(body.remark or "").strip()[:200],
        filters=json.dumps(filters, ensure_ascii=False, sort_keys=True),
        is_enabled=True,
        extra="{}",
        created_by=current_user.username,
    )
    db.add(preset)
    db.commit()
    db.refresh(preset)

    # 快捷方式保存属高频个人操作，不写系统日志（避免污染系统日志页）
    return ApiResponse(code=0, message="ok", data=_preset_to_dict(preset), request_id=str(uuid.uuid4()))


@router.patch("/{preset_id}")
def update_preset(preset_id: int, body: PresetUpdate, request: Request, db: Session = Depends(get_db),
                  current_user: AuthContext = Depends(get_current_user)):
    preset = db.execute(
        select(AlertSearchPreset).where(AlertSearchPreset.id == preset_id)
    ).scalar_one_or_none()
    if not preset:
        raise HTTPException(status_code=404, detail="快捷方式不存在")

    changes = []
    if body.name is not None:
        name = body.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="快捷方式名称不能为空")
        if name != preset.name:
            _check_name_conflict(db, name, exclude_id=preset_id)
            preset.name = name
            changes.append("name")
    if body.remark is not None:
        preset.remark = body.remark.strip()[:200]
        changes.append("remark")
    if body.filters is not None:
        filters = _normalize_filters(body.filters)
        if not filters:
            raise HTTPException(status_code=400, detail="筛选条件不能为空")
        _check_filters_conflict(db, filters, exclude_id=preset_id)
        preset.filters = json.dumps(filters, ensure_ascii=False, sort_keys=True)
        changes.append("filters")
    if body.is_enabled is not None:
        preset.is_enabled = bool(body.is_enabled)
        changes.append("is_enabled")

    db.commit()
    db.refresh(preset)

    write_system_log(db, action="update_alert_search_preset", target_type="alert_search_preset",
                     target_id=str(preset.id),
                     detail=f"修改检索快捷方式: {preset.name}（{', '.join(changes) or '无变更'}）",
                     operator=current_user.username, ip_address=_client_ip(request))
    return ApiResponse(code=0, message="ok", data=_preset_to_dict(preset), request_id=str(uuid.uuid4()))


@router.delete("/{preset_id}")
def delete_preset(preset_id: int, db: Session = Depends(get_db),
                  current_user: AuthContext = Depends(get_current_user)):
    preset = db.execute(
        select(AlertSearchPreset).where(AlertSearchPreset.id == preset_id)
    ).scalar_one_or_none()
    if not preset:
        raise HTTPException(status_code=404, detail="快捷方式不存在")

    db.delete(preset)
    db.commit()

    # 快捷方式删除属高频个人操作，不写系统日志（避免污染系统日志页）
    return ApiResponse(code=0, message="ok", data={"message": "已删除"}, request_id=str(uuid.uuid4()))
