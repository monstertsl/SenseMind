"""日志检索服务 —— 条件构建器 → ES DSL + Mapping 查询"""

import hashlib
import json
import logging
from typing import Optional
from .es_reader import get_es_reader
from . import get_cache
from ..schemas import LogSearchData, LogItemData, MappingData, FieldMappingItem

logger = logging.getLogger(__name__)

# 字段中文别名（AI 研判字段 + 常用 Suricata/Zeek 字段）
FIELD_ALIASES = {
    "_id": ("原始日志ID", "keyword", "基础", "abc123def456"),
    "@timestamp": ("时间戳", "date", "基础", "2026-07-03T10:00:00Z"),
    "source.ip": ("源IP", "ip", "网络", "192.168.1.100"),
    "source.port": ("源端口", "long", "网络", "54321"),
    "destination.ip": ("目的IP", "ip", "网络", "10.0.0.5"),
    "destination.port": ("目的端口", "long", "网络", "443"),
    "network.transport": ("传输协议", "keyword", "网络", "tcp"),
    "network.community_id": ("社区ID", "keyword", "网络", "1:abc..."),
    "event.kind": ("事件类型", "keyword", "基础", "alert"),
    "event.dataset": ("数据集", "keyword", "基础", "suricata.eve"),
    "event.module": ("模块", "keyword", "基础", "suricata"),
    "suricata.eve.alert.signature": ("告警签名", "text", "Suricata", "ET POLICY..."),
    "suricata.eve.alert.signature_id": ("签名ID", "long", "Suricata", "2000001"),
    "suricata.eve.alert.category": ("告警分类", "keyword", "Suricata", "Attempted Administrator Privilege Gain"),
    "suricata.eve.alert.severity": ("严重等级", "long", "Suricata", "1"),
    "suricata.eve.http.http_method": ("HTTP方法", "keyword", "Suricata", "GET"),
    "suricata.eve.http.url": ("HTTP URL", "text", "Suricata", "/admin?id=1"),
    "suricata.eve.http.hostname": ("HTTP主机", "keyword", "Suricata", "example.com"),
    "suricata.eve.payload_printable": ("Payload", "text", "Suricata", "GET / HTTP/1.1..."),
    "ai.alert_timestamp": ("AI研判时间", "date", "AI研判", "2026-07-03T10:00:00Z"),
    "ai.source_ip": ("AI源IP", "ip", "AI研判", "192.168.1.100"),
    "ai.source_port": ("AI源端口", "long", "AI研判", "54321"),
    "ai.destination_ip": ("AI目的IP", "ip", "AI研判", "10.0.0.5"),
    "ai.destination_port": ("AI目的端口", "long", "AI研判", "443"),
    "ai.soc_name": ("告警类型", "keyword", "AI研判", "Web应用攻击"),
    "ai.alert_signature": ("威胁名", "text", "AI研判", "SQL注入"),
    "ai.confidence": ("可信度", "float", "AI研判", "0.85"),
    "ai.attack_chain": ("溯源分析", "text", "AI研判", "攻击者通过..."),
    "ai.handling_suggestion": ("处置建议", "text", "AI研判", "1. 封禁源IP..."),
    "ai.payload": ("Payload", "text", "AI研判", "GET /admin?id=1"),
    "ai.source_alert_id": ("AI原始日志ID", "keyword", "AI研判", "abc123"),
    "ai.threat_verdict": ("威胁判定", "keyword", "AI研判", "确认威胁"),
    "ai.attack_result": ("攻击结果", "keyword", "AI研判", "成功"),
}


class LogService:
    # 仅存在于 soc-*（原始日志）索引的字段：查询时只搜 soc-*
    _SOC_ONLY_FIELDS = {
        "_id", "source.ip", "source.port",
        "destination.ip", "destination.port",
    }

    def __init__(self):
        self.es = get_es_reader()
        self.cache = get_cache()

    # ai.* 下的 text 字段集合：text 类型在 ES 中被分词器处理，
    # term/terms/wildcard 精确匹配必须走 .keyword 子字段才能命中
    _TEXT_FIELDS_WITH_KEYWORD = {
        "ai.soc_name", "ai.alert_signature", "ai.attack_chain",
        "ai.handling_suggestion", "ai.payload", "ai.source_alert_id",
        "ai.threat_verdict", "ai.attack_result", "ai.attack_technique",
        "ai.mitre_id", "ai.protocol",
    }

    def _resolve_field(self, field: str, op: str) -> str:
        """对 ai.* text 字段的 eq/ne/in/like 操作改用 .keyword 子字段。

        - IP/数值/date 字段维持原字段（ES 标准类型支持 term 查询）
        - like 操作对长文本字段用 match_phrase 更合理，对短文本用 wildcard+.keyword
        """
        if field in self._TEXT_FIELDS_WITH_KEYWORD and op in ("eq", "ne", "in"):
            return f"{field}.keyword"
        return field

    def _condition_to_query(self, condition) -> dict:
        """单个条件 → ES query 子句"""
        field = condition.field
        op = condition.operator
        value = condition.value

        # _id 是 ES 元数据字段，直接用 term 查询
        if field == "_id":
            if op == "eq":
                return {"term": {"_id": value}}
            if op == "ne":
                return {"bool": {"must_not": [{"term": {"_id": value}}]}}
            if op == "in":
                values = value if isinstance(value, list) else [v.strip() for v in str(value).split(",") if v.strip()]
                return {"terms": {"_id": values}}

        if op == "eq":
            f = self._resolve_field(field, "eq")
            return {"term": {f: value}}
        if op == "ne":
            f = self._resolve_field(field, "ne")
            return {"bool": {"must_not": [{"term": {f: value}}]}}
        if op == "like":
            # 对 text 字段用 match_phrase 模糊匹配；对 keyword 类字段用 wildcard
            if field in self._TEXT_FIELDS_WITH_KEYWORD:
                return {"match_phrase": {field: str(value)}}
            return {"wildcard": {f"{field}.keyword": f"*{value}*"}}
        if op == "in":
            f = self._resolve_field(field, "in")
            values = value if isinstance(value, list) else [v.strip() for v in str(value).split(",") if v.strip()]
            return {"terms": {f: values}}
        if op == "gte":
            return {"range": {field: {"gte": value}}}
        if op == "lte":
            return {"range": {field: {"lte": value}}}
        if op == "range":
            # value 形如 "from,to"
            if isinstance(value, str) and "," in value:
                parts = value.split(",", 1)
                return {"range": {field: {"gte": parts[0].strip(), "lte": parts[1].strip()}}}
            return {"range": {field: {"gte": value}}}
        return {"term": {field: value}}

    def _build_query(self, body) -> dict:
        """完整查询 DSL"""
        must = []
        for c in body.conditions:
            if c.field:
                must.append(self._condition_to_query(c))

        # 全局时间范围过滤（右上角时间选择器）
        time_clause = self._build_time_filter(body)
        if time_clause:
            must.append(time_clause)

        query = {"bool": {"must": must}} if must else {"match_all": {}}

        # KQL 模式（简化：直接作为 query_string）
        if body.kql and body.kql.strip():
            query = {"query_string": {"query": body.kql, "default_field": "*"}}

        return query

    def _build_time_filter(self, body) -> Optional[dict]:
        """根据 time_range / time_from / time_to 构建 @timestamp range 子句"""
        time_from = getattr(body, "time_from", None)
        time_to = getattr(body, "time_to", None)
        time_range = getattr(body, "time_range", None)

        # 自定义时间优先
        if time_from or time_to:
            rng: dict = {}
            if time_from:
                rng["gte"] = time_from
            if time_to:
                rng["lte"] = time_to
            return {"range": {"@timestamp": rng}}

        # 预设时间范围（today/yesterday/7d/30d）
        if time_range and time_range != "custom":
            try:
                f, t = self.es.time_range_to_iso(time_range)
                return {"range": {"@timestamp": {"gte": f, "lte": t}}}
            except Exception as e:
                logger.warning("时间范围解析失败: %s", e)

        return None

    def search(self, body) -> LogSearchData:
        params_hash = hashlib.md5(
            json.dumps(body.model_dump(by_alias=True), sort_keys=True, ensure_ascii=False, default=str).encode()
        ).hexdigest()[:16]
        cache_key = f"logs:search:{params_hash}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return LogSearchData(**cached)

        # 如果条件中包含仅存在于原始日志索引的字段（_id, source.ip 等），
        # 则只搜 soc-* 但排除 soc-ai-*（AI 研判索引不含这些 ECS 字段）
        # 否则同时搜 soc-* 和 soc-ai-*
        if body.indices:
            indices = body.indices
        else:
            cond_fields = {c.field for c in body.conditions if c.field}
            if cond_fields & self._SOC_ONLY_FIELDS:
                indices = ["soc-*", "-soc-ai-*"]
            else:
                indices = ["soc-*", "soc-ai-*"]
        index = ",".join(indices)
        query = self._build_query(body)
        page = max(body.page, 1)
        page_size = min(max(body.page_size, 1), 200)
        sort_field = body.sort_field or "@timestamp"
        sort_order = body.sort_order or "desc"

        es_body = {
            "query": query,
            "from": (page - 1) * page_size,
            "size": page_size,
            "sort": [{sort_field: {"order": sort_order}}],
            "highlight": {
                "fields": {"*": {"require_field_match": False}},
                "pre_tags": ["<mark>"],
                "post_tags": ["</mark>"],
                "fragment_size": 150,
            },
        }

        resp = self.es.client.search(index=index, body=es_body)
        total = resp["hits"]["total"]["value"] if resp["hits"]["total"] else 0
        items = []
        for h in resp["hits"]["hits"]:
            src = h["_source"]
            has_ai = "_index" in h and "soc-ai" in h["_index"]
            items.append(
                LogItemData(
                    _id=h["_id"],
                    _index=h["_index"],
                    _source=src,
                    highlight=h.get("highlight"),
                    has_ai_analysis=has_ai,
                    ai_doc_id=h["_id"] if has_ai else None,
                )
            )

        data = LogSearchData(total=total, items=items)
        self.cache.set(cache_key, data.model_dump(by_alias=True, mode="json"), ttl=15)
        return data

    def get_log(self, doc_id: str, index: str) -> dict:
        cache_key = f"logs:detail:{doc_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        resp = self.es.client.get(index=index, id=doc_id)
        result = resp["_source"]
        self.cache.set(cache_key, result, ttl=60)
        return result

    def get_mapping(self, indices: list = None) -> MappingData:
        idx_str = ",".join(indices) if indices else "soc-*,soc-ai-*"
        key_hash = hashlib.md5(idx_str.encode()).hexdigest()[:8]
        cache_key = f"mapping:{key_hash}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return MappingData(**cached)

        try:
            resp = self.es.client.indices.get_mapping(index=idx_str)
            es_fields = set()
            for idx_name, idx_mapping in resp.items():
                props = idx_mapping.get("mappings", {}).get("properties", {})
                self._collect_fields(props, "", es_fields)
        except Exception as e:
            logger.warning("获取索引 Mapping 失败: %s", e)
            es_fields = set()

        # 合并本地别名定义
        fields = []
        seen = set()
        for fname, (alias, ftype, group, example) in FIELD_ALIASES.items():
            # _id 是 ES 元数据字段，不出现 mapping 但始终可用
            if fname == "_id":
                available = True
            else:
                available = fname in es_fields if es_fields else True
            fields.append(
                FieldMappingItem(
                    name=fname, alias=alias, type=ftype, example=example, group=group, available=available
                )
            )
            seen.add(fname)
        # 追加 ES 中存在但本地未定义的字段
        for fname in sorted(es_fields):
            if fname in seen:
                continue
            fields.append(
                FieldMappingItem(
                    name=fname,
                    alias=fname.split(".")[-1],
                    type="keyword",
                    example="",
                    group="其他",
                    available=True,
                )
            )

        data = MappingData(fields=fields)
        self.cache.set(cache_key, data.model_dump(), ttl=600)
        return data

    def _collect_fields(self, props: dict, prefix: str, out: set):
        for name, meta in props.items():
            full = f"{prefix}.{name}" if prefix else name
            if "properties" in meta:
                self._collect_fields(meta["properties"], full, out)
            else:
                out.add(full)

    def validate_mapping(self) -> dict:
        """校验 soc-ai-* 是否包含全部 12 字段"""
        required = [
            "ai.alert_timestamp", "ai.source_ip", "ai.source_port",
            "ai.destination_ip", "ai.destination_port", "ai.soc_name",
            "ai.alert_signature", "ai.confidence", "ai.attack_chain",
            "ai.handling_suggestion", "ai.payload", "ai.source_alert_id",
        ]
        try:
            resp = self.es.client.indices.get_mapping(index="soc-ai-*")
            es_fields = set()
            for _, idx_mapping in resp.items():
                props = idx_mapping.get("mappings", {}).get("properties", {})
                ai_props = props.get("ai", {}).get("properties", {})
                for k in ai_props:
                    es_fields.add(f"ai.{k}")
        except Exception as e:
            logger.warning("校验 Mapping 失败: %s", e)
            return {"valid": True, "missing_fields": [], "present_fields": required}

        present = [f for f in required if f in es_fields]
        missing = [f for f in required if f not in es_fields]
        return {"valid": len(missing) == 0, "missing_fields": missing, "present_fields": present}


def get_log_service() -> LogService:
    return LogService()
