"""FastAPI Webhook 服务 - 接收 Logstash 推送的告警"""

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .analyzer import AlertAnalyzer
from .es_client import ESClient
from .config import Config
from .schemas import ApiResponse
from .dedup import AlertDeduplicator
from .routers import metrics as metrics_router
from .routers import query as query_router
from .routers import logs as logs_router
from .routers import system as system_router
from .routers import auth as auth_router
from .routers import user as user_router
from .routers import system_config as system_config_router
from .routers import audit_log as audit_log_router
from .routers import llm_config as llm_config_router
from .routers import ai_bypass_rule as ai_bypass_rule_router
from .scheduler import start_scheduler, shutdown_scheduler
from .core.database import init_db, SessionLocal

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动：初始化数据库 + 启动定时任务
    try:
        init_db()
        logger.info("数据库初始化完成")
    except Exception as e:
        logger.error("数据库初始化失败: %s", e, exc_info=True)
    try:
        start_scheduler()
    except Exception as e:
        logger.error("定时任务启动失败: %s", e, exc_info=True)
    yield
    # 关闭：停止定时任务
    shutdown_scheduler()


app = FastAPI(title="SenseMind AI 分析中心", version="1.0.0", lifespan=lifespan)

# CORS：允许前端跨域访问（容器化部署中前端经 nginx 反代，仍保留以备开发模式）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册查询 API 路由
app.include_router(metrics_router.router)
app.include_router(query_router.router)
app.include_router(logs_router.router)
app.include_router(system_router.router)
# 认证与系统管理路由
app.include_router(auth_router.router)
app.include_router(user_router.router)
app.include_router(system_config_router.router)
app.include_router(audit_log_router.router)
app.include_router(llm_config_router.router)
app.include_router(ai_bypass_rule_router.router)

# 全局实例（延迟初始化）
_analyzer: AlertAnalyzer = None
_es_client: ESClient = None
_deduper: AlertDeduplicator = None


def get_analyzer() -> AlertAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = AlertAnalyzer()
    return _analyzer


def reload_analyzer() -> AlertAnalyzer:
    """重新初始化分析器（LLM 配置变更后调用）"""
    global _analyzer
    _analyzer = AlertAnalyzer()
    logger.info("分析器已重新加载，模型: %s", _analyzer.model_name)
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


def _extract_candidate_hosts(alert: dict) -> list:
    """从告警事件中提取所有可作为 Host 的候选值（已转小写、去端口）

    与 src_ip/dst_ip 的提取逻辑保持一致：从告警 JSON 的多个位置收集 host，
    任一位置命中白名单即视为匹配。覆盖：
      - Suricata HTTP:  http.hostname / http.host（旧字段 http_host 亦兼容）
      - Suricata TLS:   tls.sni / tls.server_name
      - Suricata DNS:   dns.queries[].rrname（新版本数组）/ dns.rrname（旧版本）
      - Suricata URL:   http.url 中的 host 部分（仅当为完整 URL 时）
      - Zeek HTTP:      http.host
      - Zeek SSL:       ssl.server_name
      - Zeek DNS:       dns.query
      - ECS 顶层:        source.domain / destination.domain
    注意：Suricata eve.json 的 HTTP 主机字段名为 `hostname`（非 http_host），
    此处统一按项目其他模块（models/es_client/attack_detector）的约定取值，
    避免白名单 host 匹配失效。
    """
    candidates = []

    def add(value):
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip().lower())

    # ---- Suricata ----
    eve = (alert.get("suricata", {}) or {}).get("eve", {}) or {}

    http = eve.get("http") or {}
    if isinstance(http, dict):
        # Suricata 实际字段为 hostname；旧字段 http_host / http.host 亦兼容
        add(http.get("hostname") or http.get("http_host") or http.get("host"))
        # http.url 可能是完整 URL（含 scheme://host），提取其中的 host
        url = http.get("url") or ""
        if isinstance(url, str) and "://" in url:
            add(url.split("://", 1)[1].split("/", 1)[0])

    tls = eve.get("tls") or {}
    if isinstance(tls, dict):
        add(tls.get("sni") or tls.get("server_name"))

    dns = eve.get("dns") or {}
    if isinstance(dns, dict):
        # 新版本 Suricata：rrname 在 queries 数组内
        queries = dns.get("queries") or []
        if isinstance(queries, list):
            for q in queries:
                if isinstance(q, dict):
                    add(q.get("rrname"))
        # 旧版本 Suricata：rrname 直接在 dns 下
        add(dns.get("rrname"))

    # ---- Zeek ----
    zeek = alert.get("zeek", {}) or {}
    for sub in ("http", "ssl", "dns"):
        node = zeek.get(sub) or {}
        if isinstance(node, dict):
            add(node.get("host") or node.get("server_name") or node.get("query"))

    # ---- ECS 顶层 domain 字段（部分 pipeline 会打 source.domain / destination.domain）----
    src = alert.get("source", {}) or {}
    dst = alert.get("destination", {}) or {}
    if isinstance(src, dict):
        add(src.get("domain"))
    if isinstance(dst, dict):
        add(dst.get("domain"))

    return candidates


def _host_matches(entry: str, candidate: str) -> bool:
    """域名后缀匹配（防 example.com.evil.cc 这类伪装域名）

    entry 形如 "example.com"，candidate 形如 "www.example.com" / "example.com:8080" / "www.example.com:443"。
    命中条件：
      - 完全相等：candidate == example.com
      - 子域后缀：candidate 以 ".example.com" 结尾（即任意 *.example.com）
    端口会被忽略；不会误中 "example.com.evil.cc"（它不以 ".example.com" 结尾）。
    """
    entry = (entry or "").strip().lower().rstrip(".")
    if not entry:
        return False
    candidate = (candidate or "").strip().lower().rstrip(".")
    candidate = candidate.split(":")[0].strip()  # 去掉端口
    if not candidate:
        return False
    if candidate == entry:
        return True
    if candidate.endswith("." + entry):
        return True
    return False


def _match_bypass_rule(alert: dict) -> bool:
    """检查告警是否匹配 AI 分析白名单规则

    逐条匹配白名单，四元组与 host 中空值表示通配符。
    所有非空字段都匹配才算命中。
    """
    try:
        from .db_models.ai_bypass_rule import AiBypassRule
        from sqlalchemy import select

        src_ip = alert.get("source", {}).get("ip", "")
        src_port = alert.get("source", {}).get("port", 0)
        dst_ip = alert.get("destination", {}).get("ip", "")
        dst_port = alert.get("destination", {}).get("port", 0)
        cand_hosts = _extract_candidate_hosts(alert)

        with SessionLocal() as db:
            rules = db.execute(select(AiBypassRule)).scalars().all()
            for rule in rules:
                if rule.src_ip and rule.src_ip != src_ip:
                    continue
                if rule.src_port and rule.src_port != src_port:
                    continue
                if rule.dst_ip and rule.dst_ip != dst_ip:
                    continue
                if rule.dst_port and rule.dst_port != dst_port:
                    continue
                if rule.host:
                    if not any(_host_matches(rule.host, c) for c in cand_hosts):
                        continue
                logger.info("告警命中白名单规则: %s (remark=%s)",
                           f"{rule.src_ip}:{rule.src_port}->{rule.dst_ip}:{rule.dst_port}"
                           + (f" host={rule.host}" if rule.host else ""),
                           rule.remark)
                return True
    except Exception as e:
        logger.debug("白名单匹配检查失败: %s", e)
    return False


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

    # 白名单检查：命中白名单规则的告警跳过 AI 分析
    if _match_bypass_rule(alert):
        logger.info("告警命中白名单，跳过分析: %s", signature)
        return {
            "status": "skipped",
            "message": "告警命中白名单规则，跳过分析",
        }

    # AI 分析（6阶段 Chain 编排，内部由 Triage 决定是否查询关联日志）
    # analyzer.analyze() 是同步阻塞的（含 LLM/ES 同步调用），
    # 用 asyncio.to_thread 放到线程池执行，避免阻塞事件循环导致 /health、
    # /auth/check-ip 等轻量请求超时
    try:
        analyzer = get_analyzer()
        analysis = await asyncio.to_thread(analyzer.analyze, alert)
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

                # Stage 6: 规则生成（主路径，含同步热加载）
                rule_result = analyzer._generate_main_rule(ctx, analysis, related_logs)
                if rule_result:
                    analysis["generated_rule"] = rule_result
                    # 更新 ES 文档，补写 generated_rule 字段（首次写入时无此字段）
                    try:
                        es.update_analysis(doc_id, {"generated_rule": rule_result})
                    except Exception as e:
                        logger.warning("更新 ES generated_rule 失败: %s", e)

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


@app.post("/api/v1/analyze/{doc_id}")
async def analyze_es_alert(doc_id: str):
    """
    手动触发分析 ES 中的某条告警（按 _id）
    用于前端手动触发或定时任务
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
        # 补充 _id 和 _index，_enrich_metadata 需要 alert._id 设置 source_alert_id
        alert["_id"] = hits[0]["_id"]
        alert["_index"] = hits[0]["_index"]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"告警查询失败: {e}")

    # AI 分析（6阶段 Chain 编排，内部由 Triage 决定是否查询关联日志）
    analyzer = get_analyzer()
    analysis = await asyncio.to_thread(analyzer.analyze, alert)

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
                    try:
                        es.update_analysis(doc_id_new, {"generated_rule": rule_result})
                    except Exception as e:
                        logger.warning("更新 ES generated_rule 失败: %s", e)
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

    return ApiResponse(code=0, message="ok", data={"status": "analyzed", "analysis": analysis}, request_id=str(uuid.uuid4()))
