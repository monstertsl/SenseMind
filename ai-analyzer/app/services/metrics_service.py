"""监测中心指标聚合服务 —— 风险等级 / 计数 / 攻击归因"""

import logging
from .es_reader import get_es_reader
from . import get_cache

logger = logging.getLogger(__name__)


def _determine_risk_level(stats: dict) -> str:
    """科学分级：基于攻击结果、确认威胁规模、受影响资产数

    旧方案的问题：把"确认威胁比例高"当作高风险，但这只说明检测准确率高，
    并不代表环境风险高。用户环境大部分告警都是确认威胁，导致永远显示高危。

    新方案：攻击是否成功是最强风险信号，其次看威胁规模和影响面。

    风险等级 = max(攻击成功维度, 威胁规模维度)

    攻击成功维度（最强信号）：
    - 成功攻击 > 10 → critical（大规模失陷）
    - 成功攻击 > 3  → high（多处被攻破）
    - 成功攻击 > 0  → medium（有攻击成功）
    - 无成功攻击    → 由威胁规模决定

    威胁规模维度（次要）：
    - 确认威胁 > 200 或 受影响资产 > 20 → high
    - 确认威胁 > 50  或 受影响资产 > 5  → medium
    - 其他                              → low
    """
    total = stats.get("total_alerts", 0)
    reliable = stats.get("reliable", 0)
    success = stats.get("attack_success", 0)
    victim_assets = stats.get("victim_assets", 0)

    if total == 0:
        return "healthy"

    # 攻击成功维度（最强风险信号）
    if success > 10:
        return "critical"
    if success > 3:
        return "high"
    if success > 0:
        return "medium"

    # 无成功攻击时，由威胁规模决定
    if reliable > 200 or victim_assets > 20:
        return "high"
    if reliable > 50 or victim_assets > 5:
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

        # 一次性聚合：总数 + cardinality（受害资产/攻击者）+ 可信度均值 + SOC 分布 + 判定/来源/攻击结果分布
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
                "attack_result": {"terms": {"field": "ai.attack_result.keyword", "size": 5}},
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
        result_map = {b["key"]: b["doc_count"] for b in aggs.get("attack_result", {}).get("buckets", [])}
        reliable = verdict_map.get("确认威胁", verdict_map.get("reliable", 0))
        suspicious = verdict_map.get("可疑", verdict_map.get("suspicious", 0))
        unreliable = verdict_map.get("误报", verdict_map.get("unreliable", 0))
        attack_success = result_map.get("成功", 0)
        attack_failed = result_map.get("失败", 0)
        attack_unknown = result_map.get("未知", 0)
        victim_assets = aggs.get("victim_assets", {}).get("value", 0)

        avg_conf = aggs.get("avg_confidence", {}).get("value") or 0
        # 环比：上一同等长度周期
        prev_avg = self._prev_avg_confidence(time_range)

        data = {
            "risk_level": _determine_risk_level({
                "total_alerts": total,
                "reliable": reliable,
                "attack_success": attack_success,
                "victim_assets": victim_assets,
            }),
            "total_alerts": total,
            "victim_assets": victim_assets,
            "attacker_count": aggs.get("attacker_ips", {}).get("value", 0),
            "ai_total": total,
            "ai_victim_targets": victim_assets,
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
            "attack_result_distribution": {
                "success": attack_success,
                "failed": attack_failed,
                "unknown": attack_unknown,
                "total": attack_success + attack_failed + attack_unknown,
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
