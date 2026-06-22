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

    def query_related_logs(
        self,
        community_id: str = None,
        src_ip: str = None,
        dst_ip: str = None,
        timestamp: str = None,
    ) -> list:
        """
        查询关联日志：
        1. 优先用 community_id 精确关联
        2. 回退到 src_ip/dst_ip + 时间窗口模糊关联
        """
        max_logs = self.correlation.get("max_related_logs", 20)
        time_window = self.correlation.get("time_window_seconds", 300)

        # 方式1: community_id 精确关联
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
                "_source": [
                    "@timestamp",
                    "event.module",
                    "event.kind",
                    "suricata.eve.event_type",
                    "suricata.eve.alert.signature",
                    "suricata.eve.alert.category",
                    "suricata.eve.alert.severity",
                    "network.transport",
                    "network.community_id",
                    "source.ip",
                    "source.port",
                    "destination.ip",
                    "destination.port",
                    "suricata.eve.http.http_method",
                    "suricata.eve.http.url",
                    "suricata.eve.http.hostname",
                    "suricata.eve.http.http_user_agent",
                    "suricata.eve.tls.sni",
                    "suricata.eve.dns",
                    "soc",
                ],
            }
            try:
                resp = self.client.search(index=self.alert_index, body=query)
                hits = resp["hits"]["hits"]
                if hits:
                    logger.info(
                        "community_id=%s 关联到 %d 条日志", community_id, len(hits)
                    )
                    results = []
                    for h in hits:
                        src = h["_source"]
                        src["_id"] = h["_id"]
                        src["_index"] = h["_index"]
                        results.append(src)
                    return results
            except Exception as e:
                logger.warning("community_id 查询失败: %s", e)

        # 方式2: IP + 时间窗口模糊关联
        if src_ip and timestamp:
            try:
                ts = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
                time_from = (ts - timedelta(seconds=time_window)).isoformat()
                time_to = (ts + timedelta(seconds=time_window)).isoformat()

                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "bool": {
                                        "should": [
                                            {"term": {"source.ip": src_ip}},
                                            {"term": {"destination.ip": src_ip}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                                {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}},
                            ]
                        }
                    },
                    "size": max_logs,
                    "sort": [{"@timestamp": "asc"}],
                    "_source": [
                        "@timestamp",
                        "event.module",
                        "event.kind",
                        "suricata.eve.event_type",
                        "suricata.eve.alert.signature",
                        "suricata.eve.alert.severity",
                        "network.transport",
                        "source.ip",
                        "source.port",
                        "destination.ip",
                        "destination.port",
                        "suricata.eve.http.http_method",
                        "suricata.eve.http.url",
                        "suricata.eve.http.hostname",
                        "suricata.eve.tls.sni",
                        "soc",
                    ],
                }
                resp = self.client.search(index=self.alert_index, body=query)
                hits = resp["hits"]["hits"]
                logger.info("IP=%s 时间窗口关联到 %d 条日志", src_ip, len(hits))
                results = []
                for h in hits:
                    src = h["_source"]
                    src["_id"] = h["_id"]
                    src["_index"] = h["_index"]
                    results.append(src)
                return results
            except Exception as e:
                logger.warning("IP+时间窗口查询失败: %s", e)

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
