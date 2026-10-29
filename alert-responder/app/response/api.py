"""联动处置 API：设备管理、IP 白名单、手动处置与联动日志。

统一响应外壳与邮件 API 一致：{"code":0,"message":...,"data":...,"request_id":...}
"""

import ipaddress
import uuid
from urllib.parse import unquote

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from sensemind_device import DeviceError, check_network

from ..main import get_db, require_admin
from . import registry, store
from .es_marker import mark_blocked
from .models import ResponseBlockRecord, ResponseDevice, ResponseTask, ResponseWhitelist

router = APIRouter(prefix="/api/v1/response", tags=["response"])


def _ok(message: str, data=None) -> dict:
    return {"code": 0, "message": message, "data": data, "request_id": str(uuid.uuid4())}


class DeviceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    driver: str = Field(min_length=1, max_length=64)
    config: dict = Field(default_factory=dict)
    enabled: bool = True


class DeviceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    config: dict | None = None
    enabled: bool | None = None


class DeviceTestRequest(BaseModel):
    driver: str = Field(min_length=1, max_length=64)
    config: dict = Field(default_factory=dict)


class WhitelistCreate(BaseModel):
    value: str = Field(min_length=1, max_length=64)
    note: str | None = Field(default=None, max_length=200)


class TaskCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    device_id: int
    preset_id: int
    enabled: bool = True


class TaskUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    device_id: int | None = None
    preset_id: int | None = None
    enabled: bool | None = None


class ActionRequest(BaseModel):
    """手动处置：把指定 IP 下发到指定设备封堵。"""

    device_id: int
    ip: str = Field(min_length=1, max_length=64)
    # 告警文档定位（封堵成功后用于写 blocked=true）
    event_id: str | None = Field(default=None, max_length=300)
    event_index: str | None = Field(default=None, max_length=300)


def _spec_or_404(driver: str) -> registry.DriverSpec:
    try:
        return registry.get(driver)
    except registry.DriverLoadError:
        raise HTTPException(status_code=400, detail=f"未知设备类型：{driver}") from None


def _device_or_404(db: Session, device_id: int) -> ResponseDevice:
    device = db.get(ResponseDevice, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="设备不存在")
    return device


def _run_test(spec: registry.DriverSpec, cfg: dict) -> dict:
    test_func = spec.call("test_connection")
    if test_func is None:
        return {"ok": True, "message": "该设备类型未实现连接测试"}
    try:
        result = test_func(cfg)
    except DeviceError as exc:
        return {"ok": False, "message": str(exc), "code": exc.code, "retryable": exc.retryable}
    return {"ok": bool(result.ok), "message": result.message, "detail": result.detail}


@router.get("/drivers", dependencies=[Depends(require_admin)])
def list_drivers():
    return _ok("ok", {"items": registry.manifests()})


@router.get("/drivers/example", dependencies=[Depends(require_admin)])
def download_example_driver():
    """可下载的设备脚本示例（content 为源码文本，前端自行拼成 .py 下载）。"""
    try:
        filename, content = registry.example_script()
    except registry.DriverLoadError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    return _ok("ok", {"filename": filename, "content": content})


@router.delete("/drivers/{key}", dependencies=[Depends(require_admin)])
def delete_driver_script(key: str):
    """删除上传的设备脚本；内置脚本不可删除。"""
    try:
        removed = registry.uninstall_script(key)
    except registry.DriverLoadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return _ok(f"已删除自定义脚本 {removed}.py", {"key": removed})


@router.post("/drivers/upload")
async def upload_driver(
    request: Request,
    user: dict = Depends(require_admin),
    x_script_filename: str = Header("", alias="X-Script-Filename"),
    overwrite: bool = False,
):
    """上传自定义设备脚本。

    文件名经 `X-Script-Filename` 传递（前端做 URL 编码），请求体是脚本原文；
    不使用 multipart，避免额外的解析依赖。体积先按 Content-Length 拦一次，再按实际长度拦一次。

    注意：脚本会被平台导入执行，权限等同服务进程本身，因此只做管理员准入 + 静态检查，
    真正隔离需要独立执行环境（见 DEVICE_INTEGRATION.md 的风险说明）。
    """
    declared = request.headers.get("content-length")
    limit = registry.MAX_SCRIPT_BYTES
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail=f"脚本不能超过 {limit // 1024} KB")
    content = await request.body()
    if len(content) > limit:
        raise HTTPException(status_code=413, detail=f"脚本不能超过 {limit // 1024} KB")
    filename = unquote(x_script_filename or "").strip()
    if not filename:
        raise HTTPException(status_code=400, detail="缺少文件名（请求头 X-Script-Filename）")
    try:
        spec = registry.install_script(
            filename,
            content,
            overwrite=overwrite,
            uploaded_by=str(user.get("username") or user.get("name") or ""),
        )
    except registry.DriverLoadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return _ok(
        f"脚本已上传：{spec.display_name}",
        {
            "key": spec.key,
            "display_name": spec.display_name,
            "schema_version": spec.schema_version,
            "config_schema": spec.config_schema,
            "secret_fields": list(spec.secret_fields),
            "capabilities": spec.capabilities,
            "custom": spec.custom,
            "meta": spec.meta,
        },
    )


@router.get("/devices", dependencies=[Depends(require_admin)])
def list_devices(db: Session = Depends(get_db)):
    devices = db.execute(select(ResponseDevice).order_by(ResponseDevice.id)).scalars().all()
    specs = registry.scan()
    items = [store.device_view(device, specs.get(device.driver)) for device in devices]
    return _ok("ok", {"total": len(items), "items": items})


@router.post("/devices", dependencies=[Depends(require_admin)])
def create_device(body: DeviceCreate, db: Session = Depends(get_db)):
    spec = _spec_or_404(body.driver)
    values = store.validate_config(spec, body.config)
    config, secret_fields = store.seal_config(spec, values)
    device = ResponseDevice(
        name=body.name.strip(),
        driver=spec.key,
        schema_version=spec.schema_version,
        config=config,
        secret_fields=secret_fields,
        enabled=body.enabled,
    )
    db.add(device)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="设备名称已存在") from None
    db.refresh(device)
    return _ok("设备已保存", store.device_view(device, spec))


@router.put("/devices/{device_id}", dependencies=[Depends(require_admin)])
def update_device(device_id: int, body: DeviceUpdate, db: Session = Depends(get_db)):
    device = _device_or_404(db, device_id)
    spec = _spec_or_404(device.driver)
    if body.name is not None:
        device.name = body.name.strip()
    if body.enabled is not None:
        device.enabled = body.enabled
    if body.config is not None:
        values = store.validate_config(spec, body.config, existing=device.config or {})
        device.config, device.secret_fields = store.seal_config(
            spec, values, existing=device.config or {}
        )
        device.schema_version = spec.schema_version
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="设备名称已存在") from None
    db.refresh(device)
    return _ok("设备已更新", store.device_view(device, spec))


@router.delete("/devices/{device_id}", dependencies=[Depends(require_admin)])
def delete_device(device_id: int, db: Session = Depends(get_db)):
    device = _device_or_404(db, device_id)
    referenced = db.execute(
        select(ResponseTask.id).where(ResponseTask.device_id == device_id).limit(1)
    ).first()
    if referenced:
        raise HTTPException(status_code=409, detail="设备已被联动任务引用，请先解绑")
    db.delete(device)
    db.commit()
    return _ok("设备已删除", {"id": device_id})


@router.post("/devices/test", dependencies=[Depends(require_admin)])
def test_device_config(body: DeviceTestRequest):
    spec = _spec_or_404(body.driver)
    values = store.validate_config(spec, body.config)
    cfg = dict(values)
    for name, default in store.PLATFORM_DEFAULTS.items():
        cfg.setdefault(name, default)
    return _ok("测试完成", _run_test(spec, cfg))


@router.post("/devices/{device_id}/test", dependencies=[Depends(require_admin)])
def test_saved_device(device_id: int, db: Session = Depends(get_db)):
    device = _device_or_404(db, device_id)
    spec = _spec_or_404(device.driver)
    return _ok("测试完成", _run_test(spec, store.runtime_config(device)))


def _device_names(db: Session, rows) -> dict:
    ids = {row.device_id for row in rows}
    if not ids:
        return {}
    pairs = db.execute(
        select(ResponseDevice.id, ResponseDevice.name).where(ResponseDevice.id.in_(ids))
    ).all()
    return {pair[0]: pair[1] for pair in pairs}


def _task_view(row: ResponseTask, names: dict) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "device_id": row.device_id,
        "device_name": names.get(row.device_id, ""),
        "preset_id": row.preset_id,
        "enabled": row.enabled,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.get("/tasks", dependencies=[Depends(require_admin)])
def list_tasks(db: Session = Depends(get_db)):
    rows = db.execute(select(ResponseTask).order_by(ResponseTask.id)).scalars().all()
    names = _device_names(db, rows)
    items = [_task_view(row, names) for row in rows]
    return _ok("ok", {"total": len(items), "items": items})


@router.post("/tasks", dependencies=[Depends(require_admin)])
def create_task(body: TaskCreate, db: Session = Depends(get_db)):
    _device_or_404(db, body.device_id)
    row = ResponseTask(
        name=body.name.strip(),
        device_id=body.device_id,
        preset_id=body.preset_id,
        enabled=body.enabled,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="该设备已绑定同一检索条件") from None
    db.refresh(row)
    return _ok("联动设置已保存", _task_view(row, _device_names(db, [row])))


@router.put("/tasks/{task_id}", dependencies=[Depends(require_admin)])
def update_task(task_id: int, body: TaskUpdate, db: Session = Depends(get_db)):
    row = db.get(ResponseTask, task_id)
    if row is None:
        raise HTTPException(status_code=404, detail="联动设置不存在")
    if body.device_id is not None:
        _device_or_404(db, body.device_id)
        row.device_id = body.device_id
    if body.name is not None:
        row.name = body.name.strip()
    if body.preset_id is not None:
        row.preset_id = body.preset_id
    if body.enabled is not None:
        row.enabled = body.enabled
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="该设备已绑定同一检索条件") from None
    db.refresh(row)
    return _ok("联动设置已更新", _task_view(row, _device_names(db, [row])))


@router.delete("/tasks/{task_id}", dependencies=[Depends(require_admin)])
def delete_task(task_id: int, db: Session = Depends(get_db)):
    row = db.get(ResponseTask, task_id)
    if row is None:
        raise HTTPException(status_code=404, detail="联动设置不存在")
    db.delete(row)
    db.commit()
    return _ok("联动设置已删除", {"id": task_id})


@router.get("/whitelist", dependencies=[Depends(require_admin)])
def list_whitelist(db: Session = Depends(get_db)):
    rows = db.execute(select(ResponseWhitelist).order_by(ResponseWhitelist.id)).scalars().all()
    items = [
        {
            "id": row.id,
            "value": row.value,
            "note": row.note or "",
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]
    return _ok("ok", {"total": len(items), "items": items})


@router.post("/whitelist", dependencies=[Depends(require_admin)])
def create_whitelist(body: WhitelistCreate, db: Session = Depends(get_db)):
    try:
        value = check_network(body.value)
    except DeviceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    row = ResponseWhitelist(value=value, note=(body.note or "").strip() or None)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="该 IP/CIDR 已在白名单中") from None
    db.refresh(row)
    return _ok("白名单已添加", {"id": row.id, "value": row.value, "note": row.note or ""})


@router.delete("/whitelist/{row_id}", dependencies=[Depends(require_admin)])
def delete_whitelist(row_id: int, db: Session = Depends(get_db)):
    row = db.get(ResponseWhitelist, row_id)
    if row is None:
        raise HTTPException(status_code=404, detail="白名单条目不存在")
    db.delete(row)
    db.commit()
    return _ok("白名单已删除", {"id": row_id})


def _whitelisted(db: Session, ip: str) -> bool:
    """白名单按 CIDR 存储，逐条判断目标 IP 是否落在网段内。"""
    target = ipaddress.ip_address(ip)
    for value in db.execute(select(ResponseWhitelist.value)).scalars().all():
        try:
            if target in ipaddress.ip_network(str(value), strict=False):
                return True
        except ValueError:
            continue
    return False


def _record_view(row: ResponseBlockRecord, device_names: dict, task_names: dict) -> dict:
    return {
        "id": row.id,
        "ip": row.ip,
        "action": row.action,
        "status": row.status,
        "device_id": row.device_id,
        "device_name": device_names.get(row.device_id, ""),
        "task_id": row.task_id,
        "task_name": task_names.get(row.task_id) or ("手动处置" if row.task_id == 0 else ""),
        "error_code": row.error_code or "",
        "error_message": row.error_message or "",
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.post("/actions", dependencies=[Depends(require_admin)])
def run_action(body: ActionRequest, db: Session = Depends(get_db)):
    """手动处置：一次一个 IP，成败都写一条联动日志（白名单命中跳过、不写日志）。"""
    device = _device_or_404(db, body.device_id)
    if not device.enabled:
        raise HTTPException(status_code=400, detail="设备已停用，请先启用")
    try:
        ip = str(ipaddress.ip_address(body.ip.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"非法 IP：{body.ip}") from None
    if _whitelisted(db, ip):
        return _ok("IP 在白名单内，已跳过", {"status": "skipped", "ip": ip})

    spec = _spec_or_404(device.driver)
    status, error_code, error_message = "success", None, None
    try:
        spec.call("block")(ip, store.runtime_config(device))
    except DeviceError as exc:
        status, error_code, error_message = "failed", exc.code, exc.message
    except Exception as exc:  # 脚本未预料的异常也要留痕，不能让日志缺口
        status, error_code, error_message = "failed", type(exc).__name__, str(exc)

    row = ResponseBlockRecord(
        task_id=0,
        device_id=device.id,
        ip=ip,
        action="block",
        status=status,
        error_code=error_code,
        error_message=error_message,
        event_id=body.event_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    # 需求口径：blocked=true 只在封堵成功后写入，失败不标记
    blocked = mark_blocked(body.event_index or "", body.event_id or "") if status == "success" else False

    view = _record_view(row, {device.id: device.name}, {})
    view["event_blocked"] = blocked
    if status != "success":
        return _ok("处置失败", view)
    if body.event_index and body.event_id and not blocked:
        return _ok("处置完成，但告警的已处置标记写入失败", view)
    return _ok("处置完成", view)


@router.get("/records", dependencies=[Depends(require_admin)])
def list_records(
    ip: str | None = None,
    status: str | None = None,
    action: str | None = None,
    device_id: int | None = None,
    page: int = 1,
    page_size: int = 20,
    db: Session = Depends(get_db),
):
    page = max(1, page)
    page_size = min(max(1, page_size), 200)
    stmt = select(ResponseBlockRecord)
    if ip and ip.strip():
        stmt = stmt.where(ResponseBlockRecord.ip.like(f"%{ip.strip()}%"))
    if status in ("success", "failed"):
        stmt = stmt.where(ResponseBlockRecord.status == status)
    if action in ("block", "unblock"):
        stmt = stmt.where(ResponseBlockRecord.action == action)
    if device_id:
        stmt = stmt.where(ResponseBlockRecord.device_id == device_id)

    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = (
        db.execute(
            stmt.order_by(ResponseBlockRecord.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        .scalars()
        .all()
    )
    device_names = {
        pair[0]: pair[1]
        for pair in db.execute(select(ResponseDevice.id, ResponseDevice.name)).all()
    }
    task_names = {
        pair[0]: pair[1] for pair in db.execute(select(ResponseTask.id, ResponseTask.name)).all()
    }
    items = [_record_view(row, device_names, task_names) for row in rows]
    return _ok("ok", {"total": total, "page": page, "page_size": page_size, "items": items})


@router.post("/records/{row_id}/revoke", dependencies=[Depends(require_admin)])
def revoke_record(row_id: int, db: Session = Depends(get_db)):
    """撤销一条成功的封堵：调设备解除封禁，并新增一条解封日志（历史记录不改写）。"""
    origin = db.get(ResponseBlockRecord, row_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="联动日志不存在")
    if origin.action != "block" or origin.status != "success":
        raise HTTPException(status_code=400, detail="只有成功的封堵记录可以撤销")
    device = db.get(ResponseDevice, origin.device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="设备不存在")
    if not device.enabled:
        raise HTTPException(status_code=400, detail="设备已停用，请先启用")

    spec = _spec_or_404(device.driver)
    status, error_code, error_message = "success", None, None
    try:
        spec.call("unblock")(origin.ip, store.runtime_config(device))
    except DeviceError as exc:
        status, error_code, error_message = "failed", exc.code, exc.message
    except Exception as exc:
        status, error_code, error_message = "failed", type(exc).__name__, str(exc)

    row = ResponseBlockRecord(
        task_id=origin.task_id,
        device_id=device.id,
        ip=origin.ip,
        action="unblock",
        status=status,
        error_code=error_code,
        error_message=error_message,
        event_id=origin.event_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    view = _record_view(row, {device.id: device.name}, {})
    return _ok("已撤销封堵" if status == "success" else "撤销失败", view)


@router.get("/records/devices", dependencies=[Depends(require_admin)])
def record_devices(db: Session = Depends(get_db)):
    """联动日志筛选用设备清单（含已停用设备，历史日志仍可筛选）。"""
    rows = db.execute(select(ResponseDevice.id, ResponseDevice.name).order_by(ResponseDevice.id)).all()
    return _ok("ok", {"items": [{"id": pair[0], "name": pair[1]} for pair in rows]})
