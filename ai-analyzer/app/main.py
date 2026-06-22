"""FastAPI Webhook 服务 - 接收 Logstash 推送的告警"""

import logging
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from .analyzer import AlertAnalyzer
from .es_client import ESClient
from .config import Config

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


@app.get("/health")
async def health():
    """健康检查"""
    return {"status": "ok", "service": "ai-analyzer"}


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

    logger.info("收到告警: %s", alert.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", "N/A"))

    # 提取关联信息
    community_id = alert.get("network", {}).get("community_id", "")
    src_ip = alert.get("source", {}).get("ip", "")
    dst_ip = alert.get("destination", {}).get("ip", "")
    timestamp = alert.get("@timestamp", "")

    # 查询关联日志
    es = get_es_client()
    try:
        related_logs = es.query_related_logs(
            community_id=community_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            timestamp=timestamp,
        )
    except Exception as e:
        logger.warning("关联日志查询失败，继续分析: %s", e)
        related_logs = []

    # AI 分析
    try:
        analyzer = get_analyzer()
        analysis = analyzer.analyze(alert, related_logs)
    except Exception as e:
        logger.error("AI 分析失败: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"分析失败: {e}")

    # 结果回写 ES
    try:
        doc_id = es.write_analysis(analysis)
        analysis["es_doc_id"] = doc_id
    except Exception as e:
        logger.warning("结果回写 ES 失败: %s", e)
        analysis["es_write_error"] = str(e)

    logger.info(
        "告警分析完成: %s -> %s",
        alert.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", ""),
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
        resp = es.client.get(index=cfg.elasticsearch["alert_index"], id=doc_id)
        alert = resp["_source"]
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"告警不存在: {e}")

    # 提取关联信息
    community_id = alert.get("network", {}).get("community_id", "")
    src_ip = alert.get("source", {}).get("ip", "")
    timestamp = alert.get("@timestamp", "")

    related_logs = es.query_related_logs(
        community_id=community_id,
        src_ip=src_ip,
        timestamp=timestamp,
    )

    analyzer = get_analyzer()
    analysis = analyzer.analyze(alert, related_logs)

    doc_id_new = es.write_analysis(analysis)
    analysis["es_doc_id"] = doc_id_new

    return {"status": "analyzed", "analysis": analysis}
