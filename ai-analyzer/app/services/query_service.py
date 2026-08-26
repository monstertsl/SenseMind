"""告警查询业务逻辑 —— ES DSL 构造 + 缓存编排"""

import hashlib
import json
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


def _signature_wildcard(field: str, value: str) -> dict:
    """威胁名模糊匹配：将用户输入转成子串通配查询。

    text 字段用 standard 分词后，log4 这类前缀在倒排索引里不存在独立 token，
    无法用 match/match_phrase 命中 log4j、log4shell 等。改用 wildcard 包裹
    子串（*log4*），并转义用户输入中的通配符避免误匹配。
    """
    # 转义用户输入里的 ES 通配符，仅保留首尾包裹的 *
    escaped = value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
    return {"wildcard": {field: {"value": f"*{escaped}*", "case_insensitive": True}}}


class QueryService:
    """告警查询服务"""

    def __init__(self):
        self.es = get_es_reader()
        self.cache = get_cache()

    def _build_alert_query(self, params) -> dict:
        """构造告警查询 DSL（支持 ! 前缀排除搜索）"""
        must = []
        must_not = []
        time_from, time_to = self.es.time_range_to_iso(params.time_range or "7d")
        if params.time_from:
            time_from = params.time_from
        if params.time_to:
            time_to = params.time_to
        must.append({"range": {"ai.alert_timestamp": {"gte": time_from, "lte": time_to}}})

        if params.source_ip:
            must.append({"term": {"ai.source_ip": params.source_ip}})
        if params.destination_ip:
            must.append({"term": {"ai.destination_ip": params.destination_ip}})
        if params.soc_name:
            names = [s.strip() for s in params.soc_name.split(",") if s.strip()]
            if len(names) == 1:
                must.append({"term": {"ai.soc_name": names[0]}})
            else:
                must.append({"terms": {"ai.soc_name": names}})
        if params.confidence is not None:
            must.append({"term": {"ai.confidence": params.confidence}})
        if params.alert_signature:
            must.append(_signature_wildcard("ai.alert_signature", params.alert_signature))
        if params.source_alert_id:
            must.append({"term": {"ai.source_alert_id": params.source_alert_id}})
        if params.attack_result:
            must.append({"term": {"ai.attack_result": params.attack_result}})

        # 排除条件（! 前缀）
        if params.exclude_source_ip:
            must_not.append({"term": {"ai.source_ip": params.exclude_source_ip}})
        if params.exclude_destination_ip:
            must_not.append({"term": {"ai.destination_ip": params.exclude_destination_ip}})
        if params.exclude_alert_signature:
            must_not.append(_signature_wildcard("ai.alert_signature", params.exclude_alert_signature))

        bool_clause = {"must": must}
        if must_not:
            bool_clause["must_not"] = must_not
        return {"query": {"bool": bool_clause}}

    def list_alerts(self, params) -> AlertListData:
        """分页查询告警列表（后端聚合后分页）

        流程：ES PIT + search_after 分批拉取全量数据（固定按 @timestamp desc，
        保证每组"最新分析"排最前）→ 以 source_ip + destination_ip + alert_signature
        为 key 聚合（每组代表 = 最新分析）→ 按用户 sort_field 对组排序 → 按页截取。

        关键设计（分离两个排序）：
        1. ES 拉取固定 @timestamp desc（分析生成时间，每条必不同），使 dict 聚合时
           每组首次插入即"最新分析"，与用户排序字段无关。
        2. 聚合完成后按用户 sort_field（默认 ai.alert_timestamp 原始日志时间）对组排序，
           保证前端"原始日志时间"列有序。
        """
        cache_key = f"alerts:list:{_hash_query(params.model_dump(by_alias=True))}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return AlertListData(**cached)

        body = self._build_alert_query(params)
        sort_field = params.sort_field or "ai.alert_timestamp"
        sort_order = params.sort_order or "desc"
        page = max(params.page, 1)
        page_size = min(max(params.page_size, 1), 200)

        # 聚合阶段固定按 @timestamp desc（分析生成时间，每条必不同）排序：
        # 保证同一条原始日志的多次分析中"最新一次"排最前，相邻聚合时每组代表即最新分析。
        # 用户的 sort_field 仅在聚合完成后对"组"做展示排序，不影响每组代表。
        body["sort"] = [
            {"@timestamp": {"order": "desc"}},
            {"_shard_doc": "desc"},
        ]
        body["size"] = 10000

        # 使用 PIT + search_after 分批拉取，避免单次 size 过大导致 ES range 查询异常
        pit_id = None
        all_hits = []
        try:
            pit_resp = self.es.client.open_point_in_time(
                index=self.es.ai_index, keep_alive="2m"
            )
            pit_id = pit_resp["id"]
            body["pit"] = {"id": pit_id, "keep_alive": "2m"}

            search_after = None
            while True:
                if search_after is not None:
                    body["search_after"] = search_after

                resp = self.es.client.search(body=body)
                hits = resp["hits"]["hits"]
                if not hits:
                    break
                all_hits.extend(hits)
                if len(hits) < body["size"]:
                    break
                search_after = hits[-1]["sort"]

            logger.info("list_alerts PIT search: total_hits=%d", len(all_hits))
        finally:
            if pit_id:
                try:
                    self.es.client.close_point_in_time(id=pit_id)
                except Exception:
                    pass

        # 基于 key 聚合：source_ip + destination_ip + alert_signature 相同的记录合并为一组。
        # all_hits 已按 @timestamp desc 排序，dict 首次插入的记录（每组最新分析）即代表。
        # 用 dict 而非"相邻合并"，避免同一条原始日志的多次分析被其他告警穿插时被拆成多组。
        merged_map = {}
        for h in all_hits:
            ai = h["_source"].get("ai", {})
            key = f"{ai.get('source_ip', '')}|{ai.get('destination_ip', '')}|{ai.get('alert_signature', '')}"
            if key in merged_map:
                merged_map[key].ai["alert_count"] = merged_map[key].ai.get("alert_count", 1) + 1
            else:
                ai["alert_count"] = 1
                merged_map[key] = AlertItemData(_id=h["_id"], _index=h["_index"], ai=ai)

        merged = list(merged_map.values())

        # 聚合完成后，按用户指定 sort_field 对"组"做展示排序（不影响每组代表）。
        # 默认按 ai.alert_timestamp（原始日志时间）排序，保证前端时间列有序。
        key_name = sort_field.removeprefix("ai.")

        def _sort_key(item: AlertItemData):
            val = item.ai.get(key_name)
            if val is None:
                val = item.ai.get(sort_field)
            return val

        reverse = sort_order == "desc"
        try:
            merged.sort(key=lambda it: (_sort_key(it) is None, _sort_key(it)), reverse=reverse)
        except TypeError:
            # 混合类型无法比较时，退化为字符串比较
            merged.sort(key=lambda it: str(_sort_key(it)), reverse=reverse)

        total = len(merged)
        start = (page - 1) * page_size
        items = merged[start:start + page_size]

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

    def aggregations(self, field: str, time_range: str, time_from: str = None, time_to: str = None) -> AggregationData:
        """列内筛选项聚合"""
        cache_key = f"aggregations:{field}:{time_range}:{time_from}:{time_to}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return AggregationData(**cached)

        range_from, range_to = self.es.time_range_to_iso(time_range)
        if time_from:
            range_from = time_from
        if time_to:
            range_to = time_to
        time_from, time_to = range_from, range_to
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
