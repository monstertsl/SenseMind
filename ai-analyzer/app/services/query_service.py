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

    # 分组键字段：威胁名需走 text 的 keyword 子字段，才能在 ES 侧完成
    # (源IP, 目的IP, 威胁名) 分组；组代表 = 组内 @timestamp 最新的分析记录。
    _SIG_KW = "ai.alert_signature.keyword"
    _GROUP_SOURCES = [
        {"s": {"terms": {"field": "ai.source_ip", "missing_bucket": True}}},
        {"d": {"terms": {"field": "ai.destination_ip", "missing_bucket": True}}},
        {"g": {"terms": {"field": _SIG_KW, "missing_bucket": True}}},
    ]

    @staticmethod
    def _group_key(source_ip, destination_ip, signature) -> str:
        return f"{source_ip or ''}|{destination_ip or ''}|{signature or ''}"

    def list_alerts(self, params) -> AlertListData:
        """分页查询告警列表：ES 侧分组聚合 + 只取当前页代表文档

        旧实现全量拉取数万篇分析记录再在 Python 分组，耗时瓶颈是 _source 的解压与解析
        （实测 2~3s，收窄字段也省不下来）。改为两步：
        1. composite 聚合在 ES 侧分组，只回传分组键、组内条数、代表记录时间；
        2. 仅对本页的组取代表文档（page_size 条 _source）。
        排序字段不是"原始日志时间"（其余字段无 doc_values）或聚合异常时回退全量扫描。
        """
        if (params.sort_field or "ai.alert_timestamp") != "ai.alert_timestamp":
            return self._list_alerts_scan(params)
        try:
            return self._list_alerts_grouped(params)
        except Exception as e:
            logger.warning("聚合分组查询不可用，回退全量扫描: %s", e)
            return self._list_alerts_scan(params)

    def _list_alerts_grouped(self, params) -> AlertListData:
        body = self._build_alert_query(params)
        page = max(params.page, 1)
        page_size = min(max(params.page_size, 1), 200)
        reverse = (params.sort_order or "desc") == "desc"

        # 组列表只与筛选条件有关、与翻页排序无关 → 缓存后翻页/排序近乎零成本
        filter_key = _hash_query({**params.model_dump(by_alias=True),
                                  "page": None, "page_size": None,
                                  "sort_field": None, "sort_order": None})
        cache_key = f"alerts:groups:{filter_key}"
        groups = self.cache.get(cache_key)
        if groups is None:
            groups = self._fetch_groups(body)
            self.cache.set(cache_key, groups, ttl=15)

        # 按 (代表记录的原始日志时间, 分析时间) 排序，与旧实现的组顺序一致
        ordered = sorted(list(groups),
                         key=lambda g: (g["alert_timestamp"] is None,
                                        g["alert_timestamp"] or "",
                                        g["analysis_timestamp"] or ""),
                         reverse=reverse)
        total = len(ordered)
        start = (page - 1) * page_size
        page_groups = ordered[start:start + page_size]
        if not page_groups:
            return AlertListData(total=total, page=page, page_size=page_size, items=[])

        reps = self._fetch_group_reps(body, page_groups)
        items = []
        for g in page_groups:
            key = self._group_key(g["source_ip"], g["destination_ip"], g["alert_signature"])
            hit = reps.get(key)
            if hit is None:
                # 分组键与文档字段不一致（如子字段未回填）→ 回退全量扫描保证结果正确
                raise RuntimeError(f"分组代表文档缺失: {key}")
            ai = dict(hit["_source"].get("ai", {}))
            ai["alert_count"] = g["alert_count"]
            items.append(AlertItemData(_id=hit["_id"], _index=hit["_index"], ai=ai))
        return AlertListData(total=total, page=page, page_size=page_size, items=items)

    def _fetch_groups(self, query: dict) -> list:
        """composite 聚合取全部组：分组键 + 组内条数 + 代表记录时间

        composite 单次上限 10000 组，需要 after_key 翻页；top_metrics 只读 doc_values，
        比 top_hits 轻得多（实测 top_hits 每万组要 2s+）。
        """
        groups = []
        after = None
        while True:
            composite = {"size": 10000, "sources": self._GROUP_SOURCES}
            if after:
                composite["after"] = after
            body = {
                "size": 0,
                "query": query["query"],
                "aggs": {"groups": {
                    "composite": composite,
                    "aggs": {"rep": {"top_metrics": {
                        "metrics": [{"field": "ai.alert_timestamp"}, {"field": "@timestamp"}],
                        "sort": {"@timestamp": "desc"},
                    }}},
                }},
            }
            resp = self.es.client.search(index=self.es.ai_index, body=body)
            agg = resp["aggregations"]["groups"]
            for bucket in agg["buckets"]:
                metrics = ((bucket.get("rep") or {}).get("top") or [{}])[0].get("metrics", {})
                groups.append({
                    "source_ip": bucket["key"].get("s") or "",
                    "destination_ip": bucket["key"].get("d") or "",
                    "alert_signature": bucket["key"].get("g") or "",
                    "alert_count": bucket["doc_count"],
                    "alert_timestamp": metrics.get("ai.alert_timestamp"),
                    "analysis_timestamp": metrics.get("@timestamp"),
                })
            after = agg.get("after_key")
            if not after:
                break
        return groups

    def _fetch_group_reps(self, query: dict, groups: list) -> dict:
        """取本页各组的代表文档（组内 @timestamp 最新）

        查询用"本页各组"的条件收窄，参与聚合的文档只有这些组的数据，top_hits 开销可忽略。
        空的分组键不参与条件（字段缺失的文档无法用 term 命中），靠整组键回查结果。
        """
        should = []
        for g in groups:
            filters = []
            if g["source_ip"]:
                filters.append({"term": {"ai.source_ip": g["source_ip"]}})
            if g["destination_ip"]:
                filters.append({"term": {"ai.destination_ip": g["destination_ip"]}})
            if g["alert_signature"]:
                filters.append({"term": {self._SIG_KW: g["alert_signature"]}})
            should.append({"bool": {"filter": filters}})

        body = {
            "size": 0,
            "query": {"bool": {"filter": [query["query"]],
                               "should": should, "minimum_should_match": 1}},
            "aggs": {"groups": {
                "composite": {"size": 10000, "sources": self._GROUP_SOURCES},
                "aggs": {"rep": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}]}}},
            }},
        }
        resp = self.es.client.search(index=self.es.ai_index, body=body)
        reps = {}
        for bucket in resp["aggregations"]["groups"]["buckets"]:
            hits = bucket["rep"]["hits"]["hits"]
            if not hits:
                continue
            key = self._group_key(bucket["key"].get("s"), bucket["key"].get("d"), bucket["key"].get("g"))
            reps[key] = hits[0]
        return reps

    def _list_alerts_scan(self, params) -> AlertListData:
        """全量扫描兜底（旧实现）

        流程：ES PIT + search_after 分批拉取全量数据（固定按 @timestamp desc，
        保证每组"最新分析"排最前）→ 以 source_ip + destination_ip + alert_signature
        为 key 聚合（每组代表 = 最新分析）→ 按用户 sort_field 对组排序 → 按页截取。
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
