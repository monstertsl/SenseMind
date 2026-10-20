"""CRUD and scheduled delivery for alert-mail watches."""

import json
import html
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from elasticsearch import Elasticsearch
from fastapi import Depends, HTTPException
import httpx
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint, delete, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session

from .main import (
    SMTPSettings,
    _get_config,
    _saved_password,
    _valid_address,
    SessionLocal,
    app,
    engine,
    get_db,
    require_admin,
    AI_ANALYZER_URL,
    SECRET_KEY,
)

logger = logging.getLogger(__name__)
SHANGHAI_TZ = ZoneInfo("Asia/Shanghai")
ES_URL = os.environ.get("ES_URL", "https://elasticsearch:9200")
ES_READER_API_KEY = os.environ.get("ES_READER_API_KEY", "")
ES_CA_CERT = os.environ.get("ES_CA_CERT", "/usr/share/alert-responder/certs/ca.crt")
WINDOW_SECONDS = {"30m": 1800, "2h": 7200, "4h": 14400, "daily": 86400}
_es_client: Elasticsearch | None = None


class MailWatchBase(DeclarativeBase):
    pass


class AlertSearchPreset(MailWatchBase):
    """Read-only mapping of analyzer-owned search presets."""

    __tablename__ = "alert_search_presets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    filters: Mapped[str] = mapped_column(Text, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)


class AlertMailWatch(MailWatchBase):
    __tablename__ = "alert_mail_watches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    preset_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    period: Mapped[str] = mapped_column(String(16), nullable=False)
    daily_hour: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    recipients: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class AlertMailOutbox(MailWatchBase):
    __tablename__ = "alert_mail_outbox"
    __table_args__ = (UniqueConstraint("event_id", "watch_id", name="uq_alert_mail_outbox_event_watch"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(300), nullable=False)
    watch_id: Mapped[int] = mapped_column(Integer, nullable=False)
    preset_name: Mapped[str] = mapped_column(String(100), nullable=False)
    recipients: Mapped[str] = mapped_column(Text, nullable=False)
    ai_document: Mapped[str] = mapped_column(Text, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    processed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class MailWatchPayload(BaseModel):
    preset_id: int = Field(ge=1)
    period: Literal["realtime", "30m", "2h", "4h", "daily"]
    daily_hour: Optional[int] = Field(default=None, ge=0, le=23)
    recipients: list[str] = Field(min_length=1, max_length=50)


def _parse_recipients(raw: str) -> list[str]:
    try:
        values = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return values if isinstance(values, list) else []


def _next_run(period: str, daily_hour: Optional[int], after: datetime) -> datetime:
    local_after = after.astimezone(SHANGHAI_TZ)
    candidate = local_after.replace(second=0, microsecond=0)
    if period == "realtime":
        raise ValueError("实时告警由 Percolator 事件驱动，不使用周期时间")
    if period == "30m":
        candidate = local_after.replace(minute=(local_after.minute // 30) * 30, second=0, microsecond=0)
        candidate += timedelta(minutes=30)
    elif period in {"2h", "4h"}:
        step = 2 if period == "2h" else 4
        candidate = local_after.replace(hour=(local_after.hour // step) * step, minute=0, second=0, microsecond=0)
        candidate += timedelta(hours=step)
    else:
        candidate = candidate.replace(hour=daily_hour or 0, minute=0)
        if candidate <= local_after:
            candidate += timedelta(days=1)
    return candidate.astimezone(timezone.utc)


def _watch_data(db: Session, watch: AlertMailWatch) -> dict:
    preset = db.get(AlertSearchPreset, watch.preset_id)
    return {
        "id": watch.id,
        "preset_id": watch.preset_id,
        "preset_name": preset.name if preset else "快捷检索已删除",
        "period": watch.period,
        "daily_hour": watch.daily_hour,
        "recipients": _parse_recipients(watch.recipients),
        "next_run_at": watch.next_run_at.isoformat() if watch.next_run_at else None,
    }


def _validate_payload(
    payload: MailWatchPayload,
    db: Session,
    exclude_watch_id: Optional[int] = None,
) -> list[str]:
    preset = db.get(AlertSearchPreset, payload.preset_id)
    if not preset or not preset.is_enabled:
        raise HTTPException(status_code=400, detail="请选择已启用的快捷检索")
    if payload.period == "daily" and payload.daily_hour is None:
        raise HTTPException(status_code=400, detail="每天发送需要选择整点时间")
    if payload.period != "daily" and payload.daily_hour is not None:
        raise HTTPException(status_code=400, detail="仅每天发送可以设置整点时间")
    target_filters = json.dumps(
        json.loads(preset.filters or "{}"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    duplicate_query = (
        select(AlertMailWatch, AlertSearchPreset.name, AlertSearchPreset.filters)
        .join(AlertSearchPreset, AlertSearchPreset.id == AlertMailWatch.preset_id)
        .where(AlertMailWatch.period == payload.period)
    )
    if exclude_watch_id is not None:
        duplicate_query = duplicate_query.where(AlertMailWatch.id != exclude_watch_id)
    for _, duplicate_name, duplicate_filters in db.execute(duplicate_query):
        try:
            existing_filters = json.dumps(
                json.loads(duplicate_filters or "{}"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            continue
        if existing_filters == target_filters:
            raise HTTPException(
                status_code=400,
                detail=f"已存在相同检索条件和发送周期的关注告警「{duplicate_name}」，不能重复保存",
            )
    recipients = []
    for value in payload.recipients:
        recipient = _valid_address(value)
        if recipient not in recipients:
            recipients.append(recipient)
    if not recipients:
        raise HTTPException(status_code=400, detail="请至少添加一个收件邮箱")
    return recipients


def _ip_clause(field: str, value: str) -> dict:
    if not value.endswith(".*"):
        return {"term": {field: value}}
    octets = value[:-2].split(".")
    if not 1 <= len(octets) <= 3 or any(not part.isdigit() or not 0 <= int(part) <= 255 for part in octets):
        raise ValueError("不支持的 IP 通配格式")
    import ipaddress
    prefix_length = len(octets) * 8
    network = ipaddress.ip_network(f"{'.'.join(octets)}.{'.'.join(['0'] * (4 - len(octets)))}/{prefix_length}")
    return {"range": {field: {"gte": str(network.network_address), "lte": str(network.broadcast_address)}}}


def _build_query(filters: dict, start: Optional[datetime] = None, end: Optional[datetime] = None) -> dict:
    must = []
    if start is not None and end is not None:
        must.append({"range": {"ai.alert_timestamp": {"gt": start.isoformat(), "lte": end.isoformat()}}})
    must_not = []
    for key, field in (("source_ip", "ai.source_ip"), ("destination_ip", "ai.destination_ip")):
        if filters.get(key):
            must.append(_ip_clause(field, filters[key]))
    for key, field in (("soc_name", "ai.soc_name"), ("threat_verdict", "ai.threat_verdict"), ("attack_result", "ai.attack_result")):
        value = filters.get(key)
        if value:
            values = [item.strip() for item in str(value).split(",") if item.strip()]
            if len(values) == 1:
                must.append({"term": {field: values[0]}})
            elif values:
                must.append({"terms": {field: values}})
    if filters.get("confidence") is not None:
        must.append({"term": {"ai.confidence": filters["confidence"]}})
    confidence = {}
    if filters.get("confidence_min") is not None:
        confidence["gte"] = filters["confidence_min"]
    if filters.get("confidence_max") is not None:
        confidence["lte"] = filters["confidence_max"]
    if confidence:
        must.append({"range": {"ai.confidence": confidence}})
    if filters.get("alert_signature"):
        escaped = str(filters["alert_signature"]).replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
        must.append({"wildcard": {"ai.alert_signature.keyword": {"value": f"*{escaped}*", "case_insensitive": True}}})
    if filters.get("kql"):
        must.append({"query_string": {"query": filters["kql"]}})
    for key, field in (("exclude_source_ip", "ai.source_ip"), ("exclude_destination_ip", "ai.destination_ip")):
        if filters.get(key):
            must_not.append(_ip_clause(field, filters[key]))
    if filters.get("exclude_alert_signature"):
        escaped = str(filters["exclude_alert_signature"]).replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
        must_not.append({"wildcard": {"ai.alert_signature.keyword": {"value": f"*{escaped}*", "case_insensitive": True}}})
    query = {"bool": {"must": must}}
    if must_not:
        query["bool"]["must_not"] = must_not
    return query


def _sync_watch_query(watch_id: int, filters: dict) -> None:
    try:
        response = httpx.put(
            f"{AI_ANALYZER_URL}/api/internal/mail-percolator/watches/{watch_id}",
            headers={"X-Internal-Service-Token": SECRET_KEY},
            json={"filters": filters},
            timeout=10,
        )
    except httpx.HTTPError as exc:
        logger.error("同步实时邮件规则到 Percolator 失败：规则 %s，错误类型=%s", watch_id, type(exc).__name__)
        raise HTTPException(status_code=503, detail="实时告警规则同步失败，请稍后重试") from None
    if response.status_code != 200:
        logger.error("同步实时邮件规则到 Percolator 失败：规则 %s，状态码=%s", watch_id, response.status_code)
        raise HTTPException(status_code=503, detail="实时告警规则同步失败，请稍后重试")


def _delete_watch_query(watch_id: int) -> None:
    try:
        response = httpx.delete(
            f"{AI_ANALYZER_URL}/api/internal/mail-percolator/watches/{watch_id}",
            headers={"X-Internal-Service-Token": SECRET_KEY},
            timeout=10,
        )
    except httpx.HTTPError as exc:
        logger.error("删除实时邮件 Percolator 规则失败：规则 %s，错误类型=%s", watch_id, type(exc).__name__)
        raise HTTPException(status_code=503, detail="实时告警规则删除失败，请稍后重试") from None
    if response.status_code != 200:
        logger.error("删除实时邮件 Percolator 规则失败：规则 %s，状态码=%s", watch_id, response.status_code)
        raise HTTPException(status_code=503, detail="实时告警规则删除失败，请稍后重试")


def _sync_all_watch_queries() -> None:
    try:
        response = httpx.post(
            f"{AI_ANALYZER_URL}/api/internal/mail-percolator/sync",
            headers={"X-Internal-Service-Token": SECRET_KEY},
            timeout=20,
        )
    except httpx.HTTPError as exc:
        logger.error("启动时同步实时邮件规则失败，错误类型=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="实时告警规则同步失败") from None
    if response.status_code != 200:
        logger.error("启动时同步实时邮件规则失败，状态码=%s", response.status_code)
        raise HTTPException(status_code=503, detail="实时告警规则同步失败")


def _get_es_client() -> Elasticsearch:
    global _es_client
    if _es_client is not None:
        return _es_client
    if not ES_READER_API_KEY:
        raise RuntimeError("未配置 ES_READER_API_KEY")
    _es_client = Elasticsearch(ES_URL, api_key=ES_READER_API_KEY, verify_certs=True, ca_certs=ES_CA_CERT, request_timeout=20)
    return _es_client


def _mail_value(value) -> str:
    return str(value) if value not in (None, "") else "-"


def _format_beijing_time(value) -> str:
    if value in (None, ""):
        return "-"
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        logger.warning("告警时间格式无法解析，邮件中将显示占位符")
        return "-"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(SHANGHAI_TZ).strftime("%Y-%m-%d %H:%M:%S")


def _realtime_mail_body(ai: dict) -> tuple[str, str]:
    basic_fields = [
        ("时间", _format_beijing_time(ai.get("alert_timestamp"))),
        ("告警次数", ai.get("alert_count", 1)),
        ("告警类型", ai.get("soc_name")),
        ("威胁名", ai.get("alert_signature")),
        ("威胁判定", ai.get("threat_verdict")),
        ("攻击结果", ai.get("attack_result")),
        ("源 IP:端口", f"{_mail_value(ai.get('source_ip'))}:{_mail_value(ai.get('source_port'))}"),
        ("目的 IP:端口", f"{_mail_value(ai.get('destination_ip'))}:{_mail_value(ai.get('destination_port'))}"),
        ("可信度", ai.get("confidence")),
        ("原始日志ID", ai.get("source_alert_id")),
    ]
    sections = [
        ("溯源分析", ai.get("attack_chain")),
        ("处置建议", ai.get("handling_suggestion")),
        ("Payload", ai.get("payload")),
        ("Response Body", ai.get("response_body")),
    ]
    text_lines = ["基本信息"]
    text_lines.extend(f"{label}：{_mail_value(value)}" for label, value in basic_fields)
    for title, value in sections:
        text_lines.extend(["", title, _mail_value(value)])

    rows = "".join(
        f'<tr><th style="padding:9px 12px;text-align:left;color:#596579;font-weight:500;border-bottom:1px solid #e7ebf0">{html.escape(label)}</th>'
        f'<td style="padding:9px 12px;color:#172033;border-bottom:1px solid #e7ebf0;word-break:break-all">{html.escape(_mail_value(value))}</td></tr>'
        for label, value in basic_fields
    )
    section_html = "".join(
        f'<section style="margin-top:22px"><h3 style="margin:0 0 9px;color:#172033;font-size:15px">{html.escape(title)}</h3>'
        f'<div style="white-space:pre-wrap;word-break:break-word;color:#344054;background:#f7f9fb;padding:12px;border-radius:4px">{html.escape(_mail_value(value))}</div></section>'
        for title, value in sections
    )
    html_body = (
        '<div style="font-family:Arial,sans-serif;color:#172033;max-width:760px">'
        '<h2 style="margin:0 0 18px;font-size:18px">基本信息</h2>'
        f'<table role="presentation" style="width:100%;border-collapse:collapse">{rows}</table>'
        f'{section_html}</div>'
    )
    return "\n".join(text_lines), html_body


def _batch_mail_body(hits: list[dict], start: datetime, end: datetime) -> tuple[str, str]:
    columns = (
        ("时间", "alert_timestamp"),
        ("源地址", "source_ip"),
        ("目的地址", "destination_ip"),
        ("告警类型", "soc_name"),
        ("威胁名", "alert_signature"),
        ("原始日志ID", "source_alert_id"),
    )
    records = [hit.get("_source", {}).get("ai", {}) for hit in hits]
    header = "|".join(label for label, _ in columns)
    text_rows = [header]
    html_headers = "".join(f'<th style="padding:9px 10px;text-align:left;background:#f1f4f7;border-bottom:1px solid #dce2e8">{label}</th>' for label, _ in columns)
    html_rows = []
    for ai in records:
        values = [
            _format_beijing_time(ai.get(key)) if key == "alert_timestamp" else _mail_value(ai.get(key))
            for _, key in columns
        ]
        text_rows.append("|".join(values))
        html_rows.append("<tr>" + "".join(
            f'<td style="padding:9px 10px;border-bottom:1px solid #e7ebf0;word-break:break-all">{html.escape(value)}</td>'
            for value in values
        ) + "</tr>")
    window = f"{start.astimezone(SHANGHAI_TZ):%Y-%m-%d %H:%M:%S} 至 {end.astimezone(SHANGHAI_TZ):%Y-%m-%d %H:%M:%S}（北京时间）"
    text_body = f"告警数量：{len(hits)}\n{window}\n\n" + "\n".join(text_rows)
    html_body = (
        '<div style="font-family:Arial,sans-serif;color:#172033">'
        f'<p style="margin:0 0 6px">告警数量：{len(hits)}</p><p style="margin:0 0 16px;color:#596579">{html.escape(window)}</p>'
        '<table role="presentation" style="width:100%;border-collapse:collapse;font-size:13px">'
        f'<thead><tr>{html_headers}</tr></thead><tbody>{"".join(html_rows)}</tbody></table></div>'
    )
    return text_body, html_body


def _send_watch_email(
    db: Session,
    recipients: list[str],
    preset_name: str,
    period: str,
    hits: list[dict],
    start: datetime,
    end: datetime,
) -> None:
    from .main import _send_configured_email

    cfg = _get_config(db)
    settings = SMTPSettings(
        protocol=cfg.mail_protocol,
        host=cfg.mail_host,
        port=cfg.mail_port,
        username=cfg.mail_username,
        password=_saved_password(cfg),
        use_ssl=cfg.mail_use_ssl,
        sender_name=cfg.mail_sender_name,
    )
    if period == "realtime":
        ai = hits[0].get("_source", {}).get("ai", {})
        text_body, html_body = _realtime_mail_body(ai)
        subject = f"SenseMind 实时告警：{ai.get('alert_signature') or preset_name}"
    else:
        text_body, html_body = _batch_mail_body(hits, start, end)
        subject = f"SenseMind 关注告警：{preset_name}（{len(hits)} 条）"
    _send_configured_email(settings, recipients, subject, text_body, html_body)


def _process_realtime_outbox() -> None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        rows = db.execute(
            select(AlertMailOutbox)
            .where(
                AlertMailOutbox.processed_at.is_(None),
                AlertMailOutbox.next_attempt_at <= now,
            )
            .order_by(AlertMailOutbox.id)
            .limit(50)
            .with_for_update(skip_locked=True)
        ).scalars().all()
        for item in rows:
            sent = False
            try:
                ai = json.loads(item.ai_document)
                recipients = _parse_recipients(item.recipients)
                hit = {"_source": {"ai": ai}}
                for attempt in range(3):
                    try:
                        _send_watch_email(
                            db,
                            recipients,
                            item.preset_name,
                            "realtime",
                            [hit],
                            now,
                            now,
                        )
                        sent = True
                        break
                    except Exception as exc:
                        if attempt == 2:
                            logger.error(
                                "实时告警邮件发送失败：规则 %s，事件 %s，错误类型=%s",
                                item.watch_id,
                                item.event_id,
                                type(exc).__name__,
                            )
            except (TypeError, ValueError) as exc:
                logger.error("实时告警 outbox 数据无效：记录 %s，错误类型=%s", item.id, type(exc).__name__)
                sent = True

            if sent:
                db.delete(item)
            else:
                item.attempts += 1
                delay_seconds = min(300, 5 * (2 ** min(item.attempts, 6)))
                item.next_attempt_at = now + timedelta(seconds=delay_seconds)
            db.commit()


def _process_due_watches() -> None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        due_ids = db.execute(
            select(AlertMailWatch.id).where(
                AlertMailWatch.period != "realtime",
                AlertMailWatch.next_run_at <= now,
            )
        ).scalars().all()
    for watch_id in due_ids:
        with SessionLocal() as db:
            watch = db.execute(
                select(AlertMailWatch).where(AlertMailWatch.id == watch_id, AlertMailWatch.next_run_at <= now).with_for_update(skip_locked=True)
            ).scalar_one_or_none()
            if not watch:
                continue
            period, daily_hour, preset_id = watch.period, watch.daily_hour, watch.preset_id
            scheduled_at = watch.next_run_at
            if scheduled_at is None:
                logger.error("关注告警缺少下次执行时间：规则 %s，周期=%s", watch_id, period)
                continue
            recipients = _parse_recipients(watch.recipients)
            watch.next_run_at = _next_run(period, daily_hour, scheduled_at)
            db.commit()
            preset = db.get(AlertSearchPreset, preset_id)
            if not preset or not preset.is_enabled or not recipients:
                logger.warning("关注告警跳过：规则 %s 的快捷检索已删除/停用或收件人为空", watch_id)
                continue
            try:
                end = scheduled_at.astimezone(timezone.utc)
                start = end - timedelta(seconds=WINDOW_SECONDS[period])
                filters = json.loads(preset.filters or "{}")
                result = _get_es_client().search(
                    index="soc-ai-*",
                    size=200,
                    sort=[{"ai.alert_timestamp": {"order": "desc"}}],
                    source_includes=[
                        "ai.alert_timestamp", "ai.alert_count", "ai.source_ip", "ai.source_port",
                        "ai.destination_ip", "ai.destination_port", "ai.alert_signature", "ai.soc_name",
                        "ai.threat_verdict", "ai.attack_result", "ai.confidence", "ai.source_alert_id",
                        "ai.attack_chain", "ai.handling_suggestion", "ai.payload", "ai.response_body",
                    ],
                    query=_build_query(filters, start, end),
                )
                hits = result["hits"]["hits"]
                if hits:
                    sent = False
                    for attempt in range(3):
                        try:
                            _send_watch_email(db, recipients, preset.name, period, hits, start, end)
                            sent = True
                            break
                        except Exception as exc:
                            if attempt == 2:
                                logger.error("关注告警邮件发送失败：规则 %s，错误类型=%s", watch_id, type(exc).__name__)
                    if not sent:
                        continue
                logger.info("关注告警处理完成：规则 %s，窗口起点=%s，命中=%s", watch_id, start.isoformat(), len(hits))
            except Exception as exc:
                logger.error("关注告警查询失败：规则 %s，错误类型=%s", watch_id, type(exc).__name__)


@app.get("/api/v1/alert-mail-watches")
def list_mail_watches(db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    watches = db.execute(select(AlertMailWatch).order_by(AlertMailWatch.created_at.desc())).scalars().all()
    return {"code": 0, "message": "ok", "data": [_watch_data(db, watch) for watch in watches], "request_id": str(uuid.uuid4())}


@app.post("/api/v1/alert-mail-watches")
def create_mail_watch(payload: MailWatchPayload, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    recipients = _validate_payload(payload, db)
    watch = AlertMailWatch(
        preset_id=payload.preset_id,
        period=payload.period,
        daily_hour=payload.daily_hour,
        recipients=json.dumps(recipients, ensure_ascii=False),
        next_run_at=(
            None if payload.period == "realtime"
            else _next_run(payload.period, payload.daily_hour, datetime.now(timezone.utc))
        ),
    )
    db.add(watch)
    db.flush()
    if payload.period == "realtime":
        preset = db.get(AlertSearchPreset, payload.preset_id)
        _sync_watch_query(watch.id, json.loads(preset.filters or "{}"))
    db.commit()
    db.refresh(watch)
    return {"code": 0, "message": "ok", "data": _watch_data(db, watch), "request_id": str(uuid.uuid4())}


@app.put("/api/v1/alert-mail-watches/{watch_id}")
def update_mail_watch(watch_id: int, payload: MailWatchPayload, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    watch = db.get(AlertMailWatch, watch_id)
    if not watch:
        raise HTTPException(status_code=404, detail="关注告警不存在")
    recipients = _validate_payload(payload, db, exclude_watch_id=watch_id)
    watch.preset_id = payload.preset_id
    watch.period = payload.period
    watch.daily_hour = payload.daily_hour
    watch.recipients = json.dumps(recipients, ensure_ascii=False)
    watch.next_run_at = (
        None if payload.period == "realtime"
        else _next_run(payload.period, payload.daily_hour, datetime.now(timezone.utc))
    )
    if payload.period == "realtime":
        preset = db.get(AlertSearchPreset, payload.preset_id)
        _sync_watch_query(watch.id, json.loads(preset.filters or "{}"))
    else:
        _delete_watch_query(watch.id)
    db.commit()
    db.refresh(watch)
    return {"code": 0, "message": "ok", "data": _watch_data(db, watch), "request_id": str(uuid.uuid4())}


@app.delete("/api/v1/alert-mail-watches/{watch_id}")
def delete_mail_watch(watch_id: int, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    watch = db.get(AlertMailWatch, watch_id)
    if not watch:
        raise HTTPException(status_code=404, detail="关注告警不存在")
    _delete_watch_query(watch.id)
    db.delete(watch)
    db.commit()
    return {"code": 0, "message": "已删除", "data": {"message": "已删除"}, "request_id": str(uuid.uuid4())}


def start_scheduler() -> None:
    MailWatchBase.metadata.create_all(engine, tables=[AlertMailWatch.__table__, AlertMailOutbox.__table__])
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE alert_mail_watches ALTER COLUMN next_run_at DROP NOT NULL")
        connection.exec_driver_sql("UPDATE alert_mail_watches SET next_run_at = NULL WHERE period = 'realtime'")
        connection.exec_driver_sql("DELETE FROM alert_mail_outbox WHERE processed_at IS NOT NULL")
    try:
        _sync_all_watch_queries()
    except HTTPException:
        logger.exception("启动时同步所有实时邮件规则失败")
    scheduler = BackgroundScheduler(timezone="Asia/Shanghai")
    scheduler.add_job(_process_due_watches, "interval", seconds=5, id="alert_mail_watches", max_instances=1, coalesce=True)
    scheduler.add_job(_process_realtime_outbox, "interval", seconds=2, id="realtime_mail_outbox", max_instances=1, coalesce=True)
    scheduler.start()
    app.state.mail_watch_scheduler = scheduler


def stop_scheduler() -> None:
    scheduler = getattr(app.state, "mail_watch_scheduler", None)
    if scheduler:
        scheduler.shutdown(wait=False)
    if _es_client is not None:
        _es_client.close()


app.router.on_startup.append(start_scheduler)
app.router.on_shutdown.append(stop_scheduler)
