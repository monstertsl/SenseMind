"""自动联动封堵：消费 `response_pending_actions`。

ai-analyzer 侧用 Percolator 命中联动设置后把源 IP 写进待执行表，这里按 5 秒一轮取到期的行
调用设备脚本封堵；成功后给原告警写 `blocked=true` 并删行，失败按指数退避重试，
连续失败达到上限后丢弃（失败记录已写进联动日志）。

任务/设备/预设的启停变化由 60 秒一次的全量规则同步兜底，任务增删改后另行即时触发。
"""

import logging
from datetime import datetime, timedelta, timezone

import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from ..main import AI_ANALYZER_URL, SECRET_KEY, SessionLocal
from . import executor
from .es_marker import mark_blocked
from .models import ResponseDevice, ResponsePendingAction, ResponseTask

logger = logging.getLogger(__name__)

BATCH = 20
MAX_ATTEMPTS = 5
RETRY_BASE_SECONDS = 30
RETRY_MAX_SECONDS = 1800
SYNC_INTERVAL_SECONDS = 60

_scheduler: BackgroundScheduler | None = None


def sync_task_queries() -> None:
    """让 analyzer 按当前任务/设备/预设状态重算 Percolator 查询。"""
    try:
        response = httpx.post(
            f"{AI_ANALYZER_URL}/api/internal/block-tasks/sync",
            headers={"X-Internal-Service-Token": SECRET_KEY},
            timeout=20,
        )
    except httpx.HTTPError as exc:
        logger.warning("同步联动封堵规则失败（错误类型=%s）", type(exc).__name__)
        return
    if response.status_code != 200:
        logger.warning("同步联动封堵规则失败（状态码=%s）", response.status_code)


def process_pending() -> int:
    """执行到期的待办动作，返回本轮实际处理的条数。"""
    with SessionLocal() as db:
        pending_ids = (
            db.execute(
                select(ResponsePendingAction.id)
                .where(ResponsePendingAction.next_attempt_at <= datetime.now(timezone.utc))
                .order_by(ResponsePendingAction.id)
                .limit(BATCH)
            )
            .scalars()
            .all()
        )
    handled = 0
    for pending_id in pending_ids:
        # 每条一个短会话：设备调用可能耗时，别把整轮都压在同一个事务里
        with SessionLocal() as db:
            pending = db.get(ResponsePendingAction, pending_id)
            if pending is None:
                continue
            _handle(db, pending, datetime.now(timezone.utc))
            handled += 1
    return handled


def _handle(db, pending: ResponsePendingAction, now: datetime) -> None:
    task = db.get(ResponseTask, pending.task_id)
    device = db.get(ResponseDevice, pending.device_id)
    if task is None or device is None or not task.enabled or not device.enabled:
        # 任务/设备已删或停用：没有重试意义，直接丢弃
        _drop(db, pending)
        return

    try:
        whitelisted = executor.is_whitelisted(db, pending.ip)
    except ValueError:
        logger.warning("待执行动作的 IP 非法，丢弃：任务=%s IP=%s", task.id, pending.ip)
        _drop(db, pending)
        return
    if whitelisted:
        # 与手动处置口径一致：白名单命中直接跳过，不写联动日志
        _drop(db, pending)
        return

    status, error_code, error_message = executor.run_device_action(device, pending.ip, "block")
    executor.record_action(
        db,
        device,
        pending.ip,
        "block",
        status=status,
        error_code=error_code,
        error_message=error_message,
        task_id=task.id,
        event_id=pending.event_id,
    )

    if status == "success":
        blocked = mark_blocked(pending.event_index or "", pending.event_id or "")
        logger.info(
            "联动封堵成功：任务=%s 设备=%s IP=%s%s",
            task.id,
            device.name,
            pending.ip,
            "" if blocked else "（告警已处置标记写入失败）",
        )
        _drop(db, pending)
        return

    pending.attempts += 1
    if pending.attempts >= MAX_ATTEMPTS:
        logger.warning(
            "联动封堵连续失败 %s 次，放弃：任务=%s IP=%s 原因=%s",
            pending.attempts,
            task.id,
            pending.ip,
            error_message,
        )
        _drop(db, pending)
        return
    delay = min(RETRY_BASE_SECONDS * 2 ** (pending.attempts - 1), RETRY_MAX_SECONDS)
    pending.next_attempt_at = now + timedelta(seconds=delay)
    db.commit()


def _drop(db, pending: ResponsePendingAction) -> None:
    db.delete(pending)
    db.commit()


def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        return
    scheduler = BackgroundScheduler(timezone="Asia/Shanghai")
    scheduler.add_job(
        process_pending, "interval", seconds=5, id="response_pending_actions", max_instances=1, coalesce=True
    )
    scheduler.add_job(
        sync_task_queries,
        "interval",
        seconds=SYNC_INTERVAL_SECONDS,
        id="response_block_sync",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    _scheduler = scheduler
    logger.info("联动封堵调度已启动（消费间隔 5s，规则同步间隔 %ss）", SYNC_INTERVAL_SECONDS)


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
