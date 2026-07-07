"""告警查询业务逻辑 —— ES DSL 构造 + 缓存编排"""

import hashlib
import logging
from typing import Optional
from elasticsearch import BadRequestError
from .es_reader import get_es_reader
from . import get_cache
from ..schemas import AlertListData, AlertItemData, AggregationData

logger = logging.getLogger(__name__)


def _hash_query(params: dict) -> str:
    raw = json.dumps(params, sort_keys=True, ensure_ascii=False)
    return hashlib.md5(raw.encode()).hexdigest()[:16]


import json


class QueryService:
    """告警查询服务"""

    def __init__(self):
        self.es = get_es_reader()
        self.cache = get_cache()

    def _build_alert_query(self, params) -> dict:
        """构造告警查询 DSL"""
        must = []
        time_from, time_to = self.es.time_range_to_iso(params.time_range or "7d")
        if params.time_from:
            time_from = params.time_from
        if params.time_to:
            time_to = params.time_to
        must.append({"range": {"ai.alert_timestamp": {"gte": time_from, "lte": time_to}}})

        if params.source_ip:
            must.append({"term": {"ai.source_ip.keyword": params.source_ip}})
        if params.destination_ip:
            must.append({"term": {"ai.destination_ip.keyword": params.destination_ip}})
        if params.soc_name:
            names = [s.strip() for s in params.soc_name.split(",") if s.strip()]
            if len(names) == 1:
                must.append({"term": {"ai.soc_name.keyword": names[0]}})
            else:
                must.append({"terms": {"ai.soc_name.keyword": names}})
        if params.confidence is not None:
            must.append({"term": {"ai.confidence": params.confidence}})
        if params.alert_signature:
            must.append({"match_phrase": {"ai.alert_signature": params.alert_signature}})
        if params.source_alert_id:
            must.append({"term": {"ai.source_alert_id.keyword": params.source_alert_id}})
        if params.attack_result:
            must.append({"term": {"ai.attack_result.keyword": params.attack_result}})

        return {"query": {"bool": {"must": must}}}

    def list_alerts(self, params) -> AlertListData:
        """分页查询告警列表"""
        cache_key = f"alerts:list:{_hash_query(params.model_dump(by_alias=True))}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return AlertListData(**cached)

        body = self._build_alert_query(params)
        sort_field = params.sort_field or "ai.alert_timestamp"
        sort_order = params.sort_order or "desc"
        page = max(params.page, 1)
        page_size = min(max(params.page_size, 1), 200)
        body["sort"] = [{sort_field: {"order": sort_order}}]
        body["from"] = (page - 1) * page_size
        body["size"] = page_size

        resp = self.es.client.search(index=self.es.ai_index, body=body)
        total = resp["hits"]["total"]["value"] if resp["hits"]["total"] else 0
        items = [
            AlertItemData(_id=h["_id"], _index=h["_index"], ai=h["_source"].get("ai", {}))
            for h in resp["hits"]["hits"]
        ]
        data = AlertListData(total=total, page=page, page_size=page_size, items=items)
        self.cache.set(cache_key, data.model_dump(by_alias=True, mode="json"), ttl=15)
        return data

    def get_alert(self, doc_id: str) -> Optional[dict]:
        """告警详情 + 关联原始日志"""
        cache_key = f"alerts:detail:{doc_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        resp = self.es.client.search(
            index=self.es.ai_index,
            body={"query": {"term": {"_id": doc_id}}, "size": 1},
        )
        hits = resp["hits"]["hits"]
        if not hits:
            return None
        h = hits[0]
        ai = h["_source"].get("ai", {})
        source_alert_id = ai.get("source_alert_id", "")

        related_logs = []
        if source_alert_id:
            try:
                rel = self.es.client.search(
                    index=self.es.source_index,
                    body={"query": {"term": {"_id": source_alert_id}}, "size": 1},
                )
                for r in rel["hits"]["hits"]:
                    related_logs.append({"_id": r["_id"], "_index": r["_index"], "_source": r["_source"]})
            except Exception as e:
                logger.warning("关联原始日志查询失败: %s", e)

        result = {
            "_id": h["_id"],
            "_index": h["_index"],
            "ai": ai,
            "related_logs": related_logs,
        }
        self.cache.set(cache_key, result, ttl=60)
        return result

    def aggregations(self, field: str, time_range: str) -> AggregationData:
        """列内筛选项聚合"""
        cache_key = f"aggregations:{field}:{time_range}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return AggregationData(**cached)

        time_from, time_to = self.es.time_range_to_iso(time_range)
        body = {
            "size": 0,
            "query": {"range": {"ai.alert_timestamp": {"gte": time_from, "lte": time_to}}},
            "aggs": {"buckets": {"terms": {"field": field, "size": 50}}},
        }
        try:
            resp = self.es.client.search(index=self.es.ai_index, body=body)
        except BadRequestError:
            body["aggs"]["buckets"]["terms"]["field"] = f"{field}.keyword"
            resp = self.es.client.search(index=self.es.ai_index, body=body)
        buckets = [
            {"key": b["key"], "count": b["doc_count"]}
            for b in resp.get("aggregations", {}).get("buckets", {}).get("buckets", [])
        ]
        data = AggregationData(buckets=buckets)
        self.cache.set(cache_key, data.model_dump(), ttl=300)
        return data


def get_query_service() -> QueryService:
    return QueryService()
