"""联动封堵的任务匹配与入队。

与实时邮件共用同一个 Percolator 索引和同一次 percolate：邮件 watch 的文档 ID 是
`watch_id`，联动任务的文档 ID 是 `task-<id>`，一次查询把两类命中一起取回，
再分别落到邮件 outbox 与 `response_pending_actions`。

每个启用中的联动设置（`response_tasks`）按它的快捷检索预设生成查询；命中的任务把
**源 IP** 写进待执行表，由 alert-responder 轮询下发封堵。表由 alert-responder 创建，
这里只 INSERT（不建表、不改结构）。
"""

import ipaddress
import json
import logging
from datetime import datetime, timezone

from elasticsearch import Elasticsearch
from sqlalchemy import text

from ..core.database import engine
from .mail_percolator import PERCOLATOR_INDEX, _query_from_filters, ensure_percolator_index

logger = logging.getLogger(__name__)

# 联动任务在共享 Percolator 索引里的文档 ID 前缀，用于与邮件 watch（纯数字）区分
TASK_ID_PREFIX = "task-"

# 一条 (任务, 设备, IP) 只排一次队；重复命中由唯一键吞掉
INSERT_PENDING = """
INSERT INTO response_pending_actions
    (task_id, device_id, ip, event_id, event_index, attempts, next_attempt_at, created_at)
SELECT t.id, t.device_id, :ip, :event_id, :event_index, 0, :now, :now
FROM response_tasks AS t
JOIN response_devices AS d ON d.id = t.device_id
WHERE t.id = :task_id AND t.enabled = TRUE AND d.enabled = TRUE
ON CONFLICT (task_id, device_id, ip) DO NOTHING
"""


def task_doc_id(task_id: int) -> str:
    return f"{TASK_ID_PREFIX}{task_id}"


def put_task_filters(client: Elasticsearch, task_id: int, filters: dict) -> None:
    put_task_query(client, task_id, _query_from_filters(filters))


def put_task_query(client: Elasticsearch, task_id: int, query: dict) -> None:
    ensure_percolator_index(client)
    client.index(
        index=PERCOLATOR_INDEX,
        id=task_doc_id(task_id),
        document={"task_id": task_id, "query": query},
        refresh="wait_for",
    )


def delete_task_query(client: Elasticsearch, task_id: int) -> None:
    if not client.indices.exists(index=PERCOLATOR_INDEX):
        return
    try:
        client.delete(index=PERCOLATOR_INDEX, id=task_doc_id(task_id), refresh="wait_for")
    except Exception as exc:
        if getattr(exc, "meta", None) and exc.meta.status == 404:
            return
        raise


def sync_preset_task_queries(client: Elasticsearch, preset_id: int) -> int:
    """预设改动后按任务重建查询；预设被停用/删除时清掉它名下所有任务的文档。"""
    ensure_percolator_index(client)
    with engine.connect() as connection:
        preset = connection.execute(text(
            "SELECT filters, is_enabled FROM alert_search_presets WHERE id = :preset_id"
        ), {"preset_id": preset_id}).mappings().first()
        bound = connection.execute(text(
            "SELECT id FROM response_tasks WHERE preset_id = :preset_id"
        ), {"preset_id": preset_id}).scalars().all()
        if not preset or not preset["is_enabled"]:
            active = []
        else:
            active = connection.execute(text(
                """
                SELECT t.id
                FROM response_tasks AS t
                JOIN response_devices AS d ON d.id = t.device_id
                WHERE t.preset_id = :preset_id AND t.enabled = TRUE AND d.enabled = TRUE
                """
            ), {"preset_id": preset_id}).scalars().all()
    if not active:
        for task_id in bound:
            delete_task_query(client, task_id)
        return 0
    query = _query_from_filters(json.loads(preset["filters"] or "{}"))
    for task_id in bound:
        if task_id in active:
            put_task_query(client, task_id, query)
        else:
            delete_task_query(client, task_id)
    return len(active)


def sync_all_task_queries(client: Elasticsearch) -> int:
    """按当前任务/设备/预设的启用状态全量重建，并清掉已失效的任务文档。"""
    ensure_percolator_index(client)
    with engine.connect() as connection:
        rows = connection.execute(text(
            """
            SELECT t.id, p.filters
            FROM response_tasks AS t
            JOIN alert_search_presets AS p ON p.id = t.preset_id
            JOIN response_devices AS d ON d.id = t.device_id
            WHERE t.enabled = TRUE AND d.enabled = TRUE AND p.is_enabled = TRUE
            """
        )).mappings().all()
    active_ids = {task_doc_id(row["id"]) for row in rows}
    for row in rows:
        put_task_filters(client, row["id"], json.loads(row["filters"] or "{}"))
    response = client.search(index=PERCOLATOR_INDEX, size=10000, source=["task_id"], query={"match_all": {}})
    for hit in response["hits"]["hits"]:
        if not hit["_id"].startswith(TASK_ID_PREFIX) or hit["_id"] in active_ids:
            continue
        delete_task_query(client, int(hit["_id"][len(TASK_ID_PREFIX):]))
    if rows:
        client.indices.refresh(index=PERCOLATOR_INDEX)
    return len(rows)


def enqueue_task_actions(task_ids: list, document: dict, fallback_event_id: str = "") -> int:
    """把命中任务的源 IP 写入待执行表，返回新入队条数。"""
    ip = source_ip(document)
    if not ip or not task_ids:
        return 0
    ai = document.get("ai") or {}
    params = {
        "ip": ip,
        # event_id/event_index 用于封堵成功后给原告警写 blocked=true；缺失时用兜底值占位
        "event_id": (str(ai.get("source_alert_id") or "").strip() or fallback_event_id or "unknown")[:300],
        "event_index": str(ai.get("source_alert_index") or "").strip()[:300] or None,
        "now": datetime.now(timezone.utc),
    }
    inserted = 0
    try:
        with engine.begin() as connection:
            for task_id in task_ids:
                result = connection.execute(text(INSERT_PENDING), {"task_id": int(task_id), **params})
                inserted += result.rowcount or 0
    except Exception:
        logger.exception("联动封堵入队失败：任务=%s，IP=%s", task_ids, ip)
    return inserted


def source_ip(document: dict) -> str:
    """只封源地址；非法、未指定与组播地址不入队。"""
    raw = str((document.get("ai") or {}).get("source_ip") or "").strip()
    if not raw:
        return ""
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return ""
    if ip.is_unspecified or ip.is_multicast:
        return ""
    return str(ip)
