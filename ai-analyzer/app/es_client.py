"""Elasticsearch 客户端 - 告警查询、关联日志拉取、分析结果回写"""

import logging
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from .config import Config

logger = logging.getLogger(__name__)


class ESClient:
    """ES 操作封装"""

    def __init__(self):
        cfg = Config()
        es_cfg = cfg.elasticsearch
        self.alert_index = es_cfg["alert_index"]
        self.correlation = es_cfg.get("correlation", {})
        self.client = Elasticsearch(
            es_cfg["hosts"],
            basic_auth=(es_cfg.get("username", "elastic"), cfg.es_password),
            ca_certs=es_cfg.get("ca_cert"),
            verify_certs=True,
            request_timeout=30,
            headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8"},
        )

    # 关联日志查询统一使用的 _source 字段列表（覆盖 Suricata + Zeek）
    _RELATED_SOURCE_FIELDS = [
        "@timestamp",
        "event.module",
        "event.kind",
        "event.dataset",
        "event.original",
        "suricata.eve.event_type",
        "suricata.eve.alert.signature",
        "suricata.eve.alert.signature_id",
        "suricata.eve.alert.category",
        "suricata.eve.alert.severity",
        "suricata.eve.tx_id",
        "suricata.eve.http.http_method",
        "suricata.eve.http.url",
        "suricata.eve.http.hostname",
        "suricata.eve.http.http_user_agent",
        "suricata.eve.tls.sni",
        "suricata.eve.dns",
        "suricata.eve.payload_printable",
        "network.transport",
        "network.community_id",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        # Zeek 字段
        "zeek.session_id",
        "zeek.http",
        "zeek.dns",
        "zeek.ssl",
        "zeek.connection",
        "url.original",
        "url.domain",
        "http.request.method",
        "http.response.status_code",
        "dns.question.name",
        "dns.answers",
        "dns.response_code",
        "soc",
    ]

    def query_related_logs(
        self,
        community_id: str = None,
        src_ip: str = None,
        dst_ip: str = None,
        timestamp: str = None,
    ) -> list:
        """查询关联日志：community_id 精确关联 + IP 时间窗口关联，合并去重

        策略：
        1. community_id 精确关联（同 TCP/UDP 流的所有日志，含 Suricata + Zeek）
        2. IP + 时间窗口关联（src_ip 和 dst_ip 都查，覆盖多连接/多源攻击）
        3. 两者结果合并去重（按 ES _id），按时间排序

        与旧逻辑的区别：
        - 旧: community_id 查到结果就直接返回，不再查 IP 关联 → 漏掉同 IP 不同流量的攻击
        - 新: 两种查询都执行，合并去重，同时覆盖同会话和同 IP 的关联场景
        """
        max_logs = self.correlation.get("max_related_logs", 20)
        time_window = self.correlation.get("time_window_seconds", 300)

        results = []
        seen_ids = set()

        # === 方式1: community_id 精确关联 ===
        if community_id:
            query = {
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"network.community_id.keyword": community_id}},
                            {"term": {"suricata.eve.community_id.keyword": community_id}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "size": max_logs,
                "sort": [{"@timestamp": "asc"}],
                "_source": self._RELATED_SOURCE_FIELDS,
            }
            try:
                resp = self.client.search(index=self.alert_index, body=query)
                hits = resp["hits"]["hits"]
                for h in hits:
                    if h["_id"] not in seen_ids:
                        src = h["_source"]
                        src["_id"] = h["_id"]
                        src["_index"] = h["_index"]
                        results.append(src)
                        seen_ids.add(h["_id"])
                logger.info("community_id=%s 关联到 %d 条日志", community_id, len(hits))
            except Exception as e:
                logger.warning("community_id 查询失败: %s", e)

        # === 方式2: IP + 时间窗口关联（src_ip 和 dst_ip 都查） ===
        ips_to_query = []
        if src_ip:
            ips_to_query.append(src_ip)
        if dst_ip and dst_ip != src_ip:
            ips_to_query.append(dst_ip)

        if ips_to_query and timestamp:
            try:
                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                time_from = (ts - timedelta(seconds=time_window)).isoformat()
                time_to = (ts + timedelta(seconds=time_window)).isoformat()

                ip_should = []
                for ip in ips_to_query:
                    ip_should.append({"term": {"source.ip": ip}})
                    ip_should.append({"term": {"destination.ip": ip}})

                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "bool": {
                                        "should": ip_should,
                                        "minimum_should_match": 1,
                                    }
                                },
                                {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}},
                            ]
                        }
                    },
                    "size": max_logs,
                    "sort": [{"@timestamp": "asc"}],
                    "_source": self._RELATED_SOURCE_FIELDS,
                }
                resp = self.client.search(index=self.alert_index, body=query)
                hits = resp["hits"]["hits"]
                added = 0
                for h in hits:
                    if h["_id"] not in seen_ids:
                        src = h["_source"]
                        src["_id"] = h["_id"]
                        src["_index"] = h["_index"]
                        results.append(src)
                        seen_ids.add(h["_id"])
                        added += 1
                logger.info("IP=%s 时间窗口关联到 %d 条日志（去重后新增 %d 条）",
                            ips_to_query, len(hits), added)
            except Exception as e:
                logger.warning("IP+时间窗口查询失败: %s", e)

        # 按时间排序
        results.sort(key=lambda x: x.get("@timestamp", ""))
        return results[:max_logs]

    def find_original_alert(self, community_id: str, signature_id: int,
                            timestamp: str) -> tuple:
        """查找原始告警的 ES _id 和 _index

        Logstash 推送的告警不带 _id，需要回查 ES 找到原始文档。

        Args:
            community_id: 网络会话 ID
            signature_id: Suricata 规则 SID
            timestamp: 告警时间戳

        Returns:
            (_id, _index) 元组，未找到则返回 ("", "")
        """
        if not community_id or not signature_id:
            return "", ""

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event.kind": "alert"}},
                        {"term": {"suricata.eve.alert.signature_id": signature_id}},
                        {"range": {"@timestamp": {
                            "gte": timestamp,
                            "lte": timestamp,
                        }}},
                    ],
                    "should": [
                        {"term": {"network.community_id.keyword": community_id}},
                        {"term": {"suricata.eve.community_id.keyword": community_id}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "size": 1,
            "_source": False,
        }
        try:
            resp = self.client.search(index=self.alert_index, body=query)
            hits = resp["hits"]["hits"]
            if hits:
                logger.info("找到原始告警: _id=%s, _index=%s",
                            hits[0]["_id"], hits[0]["_index"])
                return hits[0]["_id"], hits[0]["_index"]
        except Exception as e:
            logger.warning("查找原始告警失败: %s", e)

        # 宽松回查：去掉时间精确匹配，用 community_id + signature_id 查最近一条
        loose_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event.kind": "alert"}},
                        {"term": {"suricata.eve.alert.signature_id": signature_id}},
                    ],
                    "should": [
                        {"term": {"network.community_id.keyword": community_id}},
                        {"term": {"suricata.eve.community_id.keyword": community_id}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "size": 1,
            "sort": [{"@timestamp": "desc"}],
            "_source": False,
        }
        try:
            resp = self.client.search(index=self.alert_index, body=loose_query)
            hits = resp["hits"]["hits"]
            if hits:
                logger.info("宽松回查找到原始告警: _id=%s, _index=%s",
                            hits[0]["_id"], hits[0]["_index"])
                return hits[0]["_id"], hits[0]["_index"]
        except Exception as e:
            logger.warning("宽松回查原始告警失败: %s", e)

        return "", ""

    def query_src_ip_history(self, src_ip: str, hours: int = 24,
                             dst_ip: str = None) -> list:
        """查询源IP（和目的IP）的历史告警记录

        Args:
            src_ip: 源IP地址
            hours: 查询时间窗口（小时），默认最近24小时
            dst_ip: 目的IP地址（可选，同时查该 IP 的历史告警）

        Returns:
            历史告警列表
        """
        ips_to_query = [ip for ip in [src_ip, dst_ip] if ip]
        if not ips_to_query:
            return []

        time_to = datetime.utcnow().isoformat() + "Z"
        time_from = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"

        ip_should = []
        for ip in ips_to_query:
            ip_should.append({"term": {"source.ip": ip}})
            ip_should.append({"term": {"destination.ip": ip}})

        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "bool": {
                                "should": ip_should,
                                "minimum_should_match": 1,
                            }
                        },
                        {"term": {"event.kind": "alert"}},
                        {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}},
                    ]
                }
            },
            "size": 20,
            "sort": [{"@timestamp": "desc"}],
            "_source": [
                "@timestamp",
                "event.module",
                "suricata.eve.alert.signature",
                "suricata.eve.alert.signature_id",
                "suricata.eve.alert.category",
                "suricata.eve.alert.severity",
                "network.transport",
                "source.ip",
                "source.port",
                "destination.ip",
                "destination.port",
                "soc",
            ],
        }
        try:
            resp = self.client.search(index=self.alert_index, body=query)
            hits = resp["hits"]["hits"]
            logger.info("IP=%s 历史告警 %d 条 (近%d小时)", ips_to_query, len(hits), hours)
            results = []
            for h in hits:
                src = h["_source"]
                src["_id"] = h["_id"]
                src["_index"] = h["_index"]
                results.append(src)
            return results
        except Exception as e:
            logger.warning("源IP历史查询失败: %s", e)
            return []

    def write_analysis(self, analysis: dict) -> str:
        """将 AI 分析结果写入 ES"""
        cfg = Config()
        index_name = cfg.get_result_index()

        doc = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event": {"kind": "ai_analysis", "module": "ai-analyzer"},
            "ai": analysis,
        }

        resp = self.client.index(index=index_name, document=doc, refresh=True)
        doc_id = resp["_id"]
        logger.info("分析结果已写入 %s, id=%s", index_name, doc_id)
        return doc_id
