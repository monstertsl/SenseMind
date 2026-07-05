"""监测中心指标聚合服务 —— 风险等级 / 计数 / 攻击归因"""

import logging
from .es_reader import get_es_reader
from . import get_cache

logger = logging.getLogger(__name__)


def _determine_risk_level(stats: dict) -> str:
    """根据告警数与威胁比例推断风险等级（五级：healthy/low/medium/high/critical）"""
    total = stats.get("total_alerts", 0)
    reliable = stats.get("reliable", 0)
    # 无告警视为健康
    if total == 0:
        return "healthy"
    ratio = reliable / total
    if total > 500 or ratio > 0.5:
        return "critical"
    if total > 200 or ratio > 0.35:
        return "high"
    if total > 50 or ratio > 0.2:
        return "medium"
    return "low"


class MetricsService:
    def __init__(self):
        self.es = get_es_reader()
        self.cache = get_cache()

    def overview(self, time_range: str) -> dict:
        cache_key = f"metrics:overview:{time_range}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        time_from, time_to = self.es.time_range_to_iso(time_range)
        time_filter = {"range": {"ai.alert_timestamp": {"gte": time_from, "lte": time_to}}}

        # 一次性聚合：总数 + cardinality（受害资产/攻击者）+ 可信度均值 + SOC 分布 + 判定/来源分布
        body = {
            "size": 0,
            "query": time_filter,
            "aggs": {
                "victim_assets": {"cardinality": {"field": "ai.destination_ip.keyword"}},
                "attacker_ips": {"cardinality": {"field": "ai.source_ip.keyword"}},
                "avg_confidence": {"avg": {"field": "ai.confidence"}},
                "soc_dist": {"terms": {"field": "ai.soc_name.keyword", "size": 14}},
                "verdict": {"terms": {"field": "ai.threat_verdict.keyword", "size": 10}},
                "source": {"terms": {"field": "ai.analysis_source.keyword", "size": 10}},
            },
        }
        resp = self.es.client.search(index=self.es.ai_index, body=body)
        aggs = resp.get("aggregations", {})
        total = resp["hits"]["total"]["value"] if resp["hits"]["total"] else 0

        soc_dist = [
            {"category": b["key"], "count": b["doc_count"]}
            for b in aggs.get("soc_dist", {}).get("buckets", [])
        ]
        verdict_map = {b["key"]: b["doc_count"] for b in aggs.get("verdict", {}).get("buckets", [])}
        source_map = {b["key"]: b["doc_count"] for b in aggs.get("source", {}).get("buckets", [])}
        reliable = verdict_map.get("确认威胁", verdict_map.get("reliable", 0))
        suspicious = verdict_map.get("可疑", verdict_map.get("suspicious", 0))
        unreliable = verdict_map.get("误报", verdict_map.get("unreliable", 0))

        avg_conf = aggs.get("avg_confidence", {}).get("value") or 0
        # 环比：上一同等长度周期
        prev_avg = self._prev_avg_confidence(time_range)

        data = {
            "risk_level": _determine_risk_level({"total_alerts": total, "reliable": reliable}),
            "total_alerts": total,
            "victim_assets": aggs.get("victim_assets", {}).get("value", 0),
            "attacker_count": aggs.get("attacker_ips", {}).get("value", 0),
            "ai_total": total,
            "ai_victim_targets": aggs.get("victim_assets", {}).get("value", 0),
            "ai_attacker_ips": aggs.get("attacker_ips", {}).get("value", 0),
            "ai_avg_confidence": round(avg_conf, 2),
            "ai_confidence_prev": round(prev_avg, 2),
            "soc_attack_distribution": soc_dist,
            "threat_verdict_distribution": {
                "reliable": reliable,
                "suspicious": suspicious,
                "unreliable": unreliable,
                "total": reliable + suspicious + unreliable,
            },
            "threat_source_distribution": {
                "system_alert": source_map.get("alert_triage", 0),
                "semantic_analysis": source_map.get("semantic_unalerted", 0),
                "total": sum(source_map.values()),
            },
        }
        self.cache.set(cache_key, data, ttl=30)
        return data

    def _prev_avg_confidence(self, time_range: str) -> float:
        """上一周期平均可信度（环比）"""
        try:
            time_from, time_to = self.es.time_range_to_iso(time_range)
            from datetime import datetime
            f = datetime.fromisoformat(time_from.replace("Z", "+00:00"))
            t = datetime.fromisoformat(time_to.replace("Z", "+00:00"))
            span = t - f
            prev_from = (f - span).isoformat()
            prev_to = f.isoformat()
            body = {
                "size": 0,
                "query": {"range": {"ai.alert_timestamp": {"gte": prev_from, "lte": prev_to}}},
                "aggs": {"avg_confidence": {"avg": {"field": "ai.confidence"}}},
            }
            resp = self.es.client.search(index=self.es.ai_index, body=body)
            return resp.get("aggregations", {}).get("avg_confidence", {}).get("value") or 0
        except Exception as e:
            logger.warning("环比可信度查询失败: %s", e)
            return 0


def get_metrics_service() -> MetricsService:
    return MetricsService()
