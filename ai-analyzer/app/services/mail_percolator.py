"""Percolator matching and durable enqueue for real-time mail alerts."""

import ipaddress
import json
import logging
import time
from datetime import datetime, timezone

from elasticsearch import Elasticsearch
from sqlalchemy import text

from ..core.database import engine

logger = logging.getLogger(__name__)

PERCOLATOR_INDEX = ".alert-mail-watch-queries"


def ensure_mail_outbox_table() -> None:
    with engine.begin() as connection:
        connection.execute(text(
            """
            CREATE TABLE IF NOT EXISTS alert_mail_outbox (
                id BIGSERIAL PRIMARY KEY,
                event_id VARCHAR(300) NOT NULL,
                watch_id INTEGER NOT NULL,
                preset_name VARCHAR(100) NOT NULL,
                recipients TEXT NOT NULL,
                ai_document TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                processed_at TIMESTAMPTZ,
                CONSTRAINT uq_alert_mail_outbox_event_watch UNIQUE (event_id, watch_id)
            )
            """
        ))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_alert_mail_outbox_pending "
            "ON alert_mail_outbox (next_attempt_at) WHERE processed_at IS NULL"
        ))


def ensure_percolator_index(client: Elasticsearch) -> None:
    if client.indices.exists(index=PERCOLATOR_INDEX):
        return
    try:
        client.indices.create(
            index=PERCOLATOR_INDEX,
            mappings={
                "dynamic": True,
                "properties": {
                    "watch_id": {"type": "long"},
                    "query": {"type": "percolator"},
                    "@timestamp": {"type": "date"},
                    "ai": {
                        "properties": {
                            "source_ip": {"type": "ip"},
                            "destination_ip": {"type": "ip"},
                            "soc_name": {"type": "keyword"},
                            "soc_category": {"type": "keyword"},
                            "threat_verdict": {"type": "keyword"},
                            "attack_result": {"type": "keyword"},
                            "confidence": {"type": "float"},
                            "alert_timestamp": {"type": "date"},
                            "alert_count": {"type": "long"},
                            "source_port": {"type": "integer"},
                            "destination_port": {"type": "integer"},
                            "source_alert_id": {"type": "keyword"},
                            "source_alert_index": {"type": "keyword"},
                            "analysis_source": {"type": "keyword"},
                            "community_id": {"type": "keyword"},
                            "alert_signature": {
                                "type": "text",
                                "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}},
                            },
                            "attack_chain": {"type": "text"},
                            "handling_suggestion": {"type": "text"},
                            "payload": {"type": "text"},
                        }
                    },
                },
            },
        )
    except Exception as exc:
        if getattr(exc, "meta", None) and exc.meta.status == 400:
            if getattr(exc, "body", {}).get("error", {}).get("type") == "resource_already_exists_exception":
                return
        raise


def put_watch_query(client: Elasticsearch, watch_id: int, query: dict) -> None:
    ensure_percolator_index(client)
    client.index(
        index=PERCOLATOR_INDEX,
        id=str(watch_id),
        document={"watch_id": watch_id, "query": query},
        refresh="wait_for",
    )


def put_watch_filters(client: Elasticsearch, watch_id: int, filters: dict) -> None:
    put_watch_query(client, watch_id, _query_from_filters(filters))


def delete_watch_query(client: Elasticsearch, watch_id: int) -> None:
    if client.indices.exists(index=PERCOLATOR_INDEX):
        try:
            client.delete(index=PERCOLATOR_INDEX, id=str(watch_id), refresh="wait_for")
        except Exception as exc:
            if getattr(exc, "meta", None) and exc.meta.status == 404:
                return
            raise


def sync_preset_watch_queries(client: Elasticsearch, preset_id: int) -> int:
    ensure_percolator_index(client)
    with engine.connect() as connection:
        preset = connection.execute(text(
            "SELECT filters, is_enabled FROM alert_search_presets WHERE id = :preset_id"
        ), {"preset_id": preset_id}).mappings().first()
        watches = connection.execute(text(
            "SELECT id FROM alert_mail_watches WHERE preset_id = :preset_id AND period = 'realtime'"
        ), {"preset_id": preset_id}).scalars().all()
    if not preset or not preset["is_enabled"]:
        for watch_id in watches:
            delete_watch_query(client, watch_id)
        return 0
    query = _query_from_filters(json.loads(preset["filters"] or "{}"))
    for watch_id in watches:
        put_watch_query(client, watch_id, query)
    return len(watches)


def sync_all_watch_queries(client: Elasticsearch) -> int:
    ensure_percolator_index(client)
    with engine.connect() as connection:
        rows = connection.execute(text(
            """
            SELECT w.id, p.filters
            FROM alert_mail_watches AS w
            JOIN alert_search_presets AS p ON p.id = w.preset_id
            WHERE w.period = 'realtime' AND p.is_enabled = TRUE
            """
        )).mappings().all()
    active_ids = {str(row["id"]) for row in rows}
    for row in rows:
        put_watch_filters(client, row["id"], json.loads(row["filters"] or "{}"))
    response = client.search(index=PERCOLATOR_INDEX, size=10000, source=["watch_id"], query={"match_all": {}})
    for hit in response["hits"]["hits"]:
        if hit["_id"] not in active_ids:
            delete_watch_query(client, int(hit["_id"]))
    if rows:
        client.indices.refresh(index=PERCOLATOR_INDEX)
    return len(rows)


def _query_from_filters(filters: dict) -> dict:
    must = []
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
    if filters.get("blocked") is not None:
        # 与告警查询口径一致：未处置的文档没有 blocked 字段
        if filters["blocked"] in (True, "true", 1, "1"):
            must.append({"term": {"blocked": True}})
        else:
            must.append({"bool": {"must_not": [{"term": {"blocked": True}}]}})
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


def _ip_clause(field: str, value: str) -> dict:
    if not value.endswith(".*"):
        return {"term": {field: value}}
    octets = value[:-2].split(".")
    if not 1 <= len(octets) <= 3 or any(not part.isdigit() or not 0 <= int(part) <= 255 for part in octets):
        raise ValueError("不支持的 IP 通配格式")
    prefix_length = len(octets) * 8
    network = ipaddress.ip_network(f"{'.'.join(octets)}.{'.'.join(['0'] * (4 - len(octets)))}/{prefix_length}")
    return {"range": {field: {"gte": str(network.network_address), "lte": str(network.broadcast_address)}}}


def enqueue_matching_watches(client: Elasticsearch, index_name: str, doc_id: str, document: dict) -> int:
    for attempt in range(3):
        try:
            return _enqueue_matching_watches_once(client, index_name, doc_id, document)
        except Exception:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("Percolator retry loop exited unexpectedly")


def _enqueue_matching_watches_once(client: Elasticsearch, index_name: str, doc_id: str, document: dict) -> int:
    ensure_percolator_index(client)
    response = client.search(
        index=PERCOLATOR_INDEX,
        size=10000,
        source=["watch_id"],
        query={"percolate": {"field": "query", "document": document}},
    )
    watch_ids = sorted({hit["_source"]["watch_id"] for hit in response["hits"]["hits"]})
    if not watch_ids:
        return 0

    event_id = f"{index_name}:{doc_id}"
    ai_json = json.dumps(document.get("ai", {}), ensure_ascii=False)
    inserted = 0
    with engine.begin() as connection:
        for watch_id in watch_ids:
            result = connection.execute(text(
                """
                INSERT INTO alert_mail_outbox
                    (event_id, watch_id, preset_name, recipients, ai_document, next_attempt_at, created_at)
                SELECT :event_id, w.id, p.name, w.recipients, :ai_document, :now, :now
                FROM alert_mail_watches AS w
                JOIN alert_search_presets AS p ON p.id = w.preset_id
                WHERE w.id = :watch_id AND w.period = 'realtime' AND p.is_enabled = TRUE
                ON CONFLICT (event_id, watch_id) DO NOTHING
                """
            ), {
                "event_id": event_id,
                "watch_id": watch_id,
                "ai_document": ai_json,
                "now": datetime.now(timezone.utc),
            })
            inserted += result.rowcount or 0
    return inserted
