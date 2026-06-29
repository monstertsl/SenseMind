"""FastAPI Webhook 服务 - 接收 Logstash 推送的告警"""

import logging
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from .analyzer import AlertAnalyzer
from .es_client import ESClient
from .config import Config
from .dedup import AlertDeduplicator

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="SenseMind AI 分析中心", version="1.0.0")

# 全局实例（延迟初始化）
_analyzer: AlertAnalyzer = None
_es_client: ESClient = None
_deduper: AlertDeduplicator = None


def get_analyzer() -> AlertAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = AlertAnalyzer()
    return _analyzer


def get_es_client() -> ESClient:
    global _es_client
    if _es_client is None:
        _es_client = ESClient()
    return _es_client


def get_deduper() -> AlertDeduplicator:
    global _deduper
    if _deduper is None:
        cfg = Config()
        dedup_cfg = cfg.dedup
        if not dedup_cfg.get("enabled", True):
            return None
        _deduper = AlertDeduplicator(
            dedup_window=dedup_cfg.get("window_seconds", 600),
            max_entries=dedup_cfg.get("max_entries", 10000),
        )
    return _deduper


@app.get("/health")
async def health():
    """健康检查"""
    return {"status": "ok", "service": "ai-analyzer"}


@app.get("/api/dedup/stats")
async def dedup_stats():
    """去重缓存统计"""
    deduper = get_deduper()
    if not deduper:
        return {"enabled": False}
    return {"enabled": True, **deduper.stats()}


@app.get("/")
async def root():
    """根路径"""
    cfg = Config()
    return {
        "service": "SenseMind AI 分析中心",
        "model": cfg.llm["model"],
        "endpoints": {
            "health": "/health",
            "analyze": "/api/alert (POST)",
        },
    }


@app.post("/api/alert")
async def analyze_alert(request: Request):
    """
    接收 Logstash http output 推送的告警
    Logstash format=json 会推送整个事件 JSON
    """
    try:
        alert = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"无效的 JSON: {e}")

    # 提取去重维度: community_id + signature_id + source_ip
    community_id = alert.get("network", {}).get("community_id", "")
    signature_id = alert.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature_id", 0)
    signature = alert.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", "N/A")
    source_ip = alert.get("source", {}).get("ip", "")

    logger.info("收到告警: %s (community_id=%s, sid=%s, src_ip=%s)",
                signature, community_id[:20] if community_id else "N/A", signature_id, source_ip)

    # 去重检查: 同一 community_id + signature_id 或同一 source_ip + signature_id 在窗口内不重复分析
    deduper = get_deduper()
    if deduper:
        cached = deduper.check(community_id, signature_id, source_ip)
        if cached:
            logger.info("告警已去重，跳过分析: %s -> %s", signature, cached.get("verdict", "N/A"))
            return {
                "status": "deduplicated",
                "message": f"同规则告警在 {deduper.dedup_window}s 内已分析过",
                "previous_verdict": cached.get("verdict"),
                "previous_es_doc_id": cached.get("es_doc_id"),
            }

    # AI 分析（6阶段 Chain 编排，内部由 Triage 决定是否查询关联日志）
    try:
        analyzer = get_analyzer()
        analysis = analyzer.analyze(alert)
    except Exception as e:
        logger.error("AI 分析失败: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"分析失败: {e}")

    # 提取后台上下文（规则生成 + 漏报处理），不写入 ES
    bg_context = analysis.pop("_bg_context", None)

    # 结果回写 ES（主告警）— 先写主记录，让 soc-ai-* 尽快可见
    es = get_es_client()
    try:
        doc_id = es.write_analysis(analysis)
        analysis["es_doc_id"] = doc_id
    except Exception as e:
        logger.warning("结果回写 ES 失败: %s", e)
        analysis["es_write_error"] = str(e)

    # 后台执行规则生成 + 漏报处理（不阻塞 HTTP 响应）
    if bg_context:
        import threading
        def _bg_task():
            try:
                ctx = bg_context["ctx"]
                related_logs = bg_context["related_logs"]

                # Stage 6: 规则生成（主路径）
                rule_result = analyzer._generate_main_rule(ctx, analysis, related_logs)
                if rule_result:
                    analysis["generated_rule"] = rule_result

                # 漏报攻击处理
                unalerted_records = analyzer._process_unalerted_attacks(
                    ctx, analysis, related_logs
                )
                if unalerted_records:
                    for rec in unalerted_records:
                        rec["triggered_by_alert"] = doc_id
                        # source_alert_id 已在 _build_unalerted_analysis 中
                        # 指向漏报攻击自身的原始日志 _id，不覆盖
                        try:
                            es.write_analysis(rec)
                        except Exception as e:
                            logger.warning("漏报记录写入 ES 失败: %s", e)
                    logger.info("漏报攻击记录写入 %d 条", len(unalerted_records))

            except Exception as e:
                logger.error("后台规则生成/漏报处理失败: %s", e, exc_info=True)

        threading.Thread(target=_bg_task, daemon=True, name="bg-rule-unalerted").start()

    # 记录到去重缓存
    if deduper:
        deduper.record(
            community_id=community_id,
            signature_id=signature_id,
            es_doc_id=analysis.get("es_doc_id", ""),
            verdict=analysis.get("threat_verdict", ""),
            source_ip=source_ip,
        )

    logger.info(
        "告警分析完成: %s -> %s",
        signature,
        analysis.get("threat_verdict", "N/A"),
    )

    return {"status": "analyzed", "analysis": analysis}


@app.post("/api/analyze/{doc_id}")
async def analyze_es_alert(doc_id: str):
    """
    手动触发分析 ES 中的某条告警（按 _id）
    用于 Kibana 手动触发或定时任务
    """
    try:
        es = get_es_client()
        cfg = Config()
        # ES get API 不支持通配符，用 search 按 _id 查询
        resp = es.client.search(
            index=cfg.elasticsearch["alert_index"],
            body={"query": {"term": {"_id": doc_id}}, "size": 1},
        )
        hits = resp["hits"]["hits"]
        if not hits:
            raise HTTPException(status_code=404, detail=f"告警不存在: {doc_id}")
        alert = hits[0]["_source"]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"告警查询失败: {e}")

    # AI 分析（6阶段 Chain 编排，内部由 Triage 决定是否查询关联日志）
    analyzer = get_analyzer()
    analysis = analyzer.analyze(alert)

    # 提取后台上下文（规则生成 + 漏报处理），不写入 ES
    bg_context = analysis.pop("_bg_context", None)

    doc_id_new = es.write_analysis(analysis)
    analysis["es_doc_id"] = doc_id_new

    # 后台执行规则生成 + 漏报处理
    if bg_context:
        import threading
        def _bg_task_manual():
            try:
                ctx = bg_context["ctx"]
                related_logs = bg_context["related_logs"]
                rule_result = analyzer._generate_main_rule(ctx, analysis, related_logs)
                if rule_result:
                    analysis["generated_rule"] = rule_result
                unalerted_records = analyzer._process_unalerted_attacks(
                    ctx, analysis, related_logs
                )
                if unalerted_records:
                    for rec in unalerted_records:
                        rec["triggered_by_alert"] = doc_id_new
                        # source_alert_id 已在 _build_unalerted_analysis 中设置
                        try:
                            es.write_analysis(rec)
                        except Exception as e:
                            logger.warning("漏报记录写入 ES 失败: %s", e)
            except Exception as e:
                logger.error("后台规则生成/漏报处理失败: %s", e, exc_info=True)

        threading.Thread(target=_bg_task_manual, daemon=True,
                         name="bg-rule-unalerted-manual").start()

    return {"status": "analyzed", "analysis": analysis}
