"""封堵/解封的执行与留痕。

手动处置（`POST /actions`、撤销记录）与自动联动（`auto_block` 消费待执行表）
共用这里，避免两条路径对设备脚本的调用方式、失败码与日志写法出现分叉。
"""

import ipaddress
import logging

from sensemind_device import DeviceError
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import registry, store
from .models import ResponseBlockRecord, ResponseWhitelist

logger = logging.getLogger(__name__)


def is_whitelisted(db: Session, ip: str) -> bool:
    """白名单按 CIDR 存储，逐条判断目标 IP 是否落在网段内。"""
    target = ipaddress.ip_address(ip)
    for value in db.execute(select(ResponseWhitelist.value)).scalars().all():
        try:
            if target in ipaddress.ip_network(str(value), strict=False):
                return True
        except ValueError:
            continue
    return False


def run_device_action(device, ip: str, action: str) -> tuple:
    """调设备脚本执行一次动作，返回 (status, error_code, error_message)。

    脚本未预料的异常同样是 failed，只是错误码取异常类名——不能让日志缺口。
    """
    spec = registry.get(device.driver)
    try:
        spec.call(action)(ip, store.runtime_config(device))
    except DeviceError as exc:
        return "failed", exc.code, exc.message
    except Exception as exc:
        return "failed", type(exc).__name__, str(exc)
    return "success", None, None


def record_action(
    db: Session,
    device,
    ip: str,
    action: str,
    *,
    status: str,
    error_code: str | None = None,
    error_message: str | None = None,
    task_id: int = 0,
    event_id: str | None = None,
) -> ResponseBlockRecord:
    row = ResponseBlockRecord(
        task_id=task_id,
        device_id=device.id,
        ip=ip,
        action=action,
        status=status,
        error_code=error_code,
        error_message=error_message,
        event_id=event_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
