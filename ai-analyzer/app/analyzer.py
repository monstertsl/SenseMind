"""AI 分析核心 - 6 阶段 LangChain 编排

Stage 1: 告警标准化 (Normalize Chain)   - 字段提取 → AlertContext
Stage 2: 告警研判 (Triage Chain)        - AI 判断是否需要深入调查
Stage 3: 动态关联查询 (LangChain Tool)  - 根据 Triage 结果按需查询 ES
Stage 4: 知识增强 (RAG)                 - 检索安全知识库
Stage 5: 最终分析 (Analysis Chain)      - 综合输出结构化研判结果
Stage 6: 规则生成 (Rule Generator)      - 确认攻击但未触发告警时自动生成规则
"""

import logging
import time
import re
import os
import threading
from langchain_openai import ChatOpenAI
from .config import Config
from .models import AlertContext, TriageResult
from .chains.normalize import normalize_chain
from .chains.triage import create_triage_chain
from .chains.analysis import create_analysis_chain
from .chains.rule_generator import create_rule_generator_chain
from .chains.unalerted_analysis import create_unalerted_analysis_chain
from .tools.es_tools import format_logs
from .knowledge.rag import create_knowledge_retriever
from .es_client import ESClient
from .attack_detector import find_unalerted_attacks
from .http_utils import decode_http_body

logger = logging.getLogger(__name__)


# 语义检测攻击类型 → SOC 分类 / MITRE / 技术名 映射
ATTACK_TYPE_SOC_MAPPING = {
    "sql_injection":         {"soc_category": "01", "soc_name": "Web应用攻击", "mitre_id": "T1190", "technique": "SQL注入"},
    "ognl_injection":        {"soc_category": "01", "soc_name": "Web应用攻击", "mitre_id": "T1190", "technique": "OGNL注入"},
    "ssti":                  {"soc_category": "01", "soc_name": "Web应用攻击", "mitre_id": "T1190", "technique": "SSTI模板注入"},
    "ssrf":                  {"soc_category": "01", "soc_name": "Web应用攻击", "mitre_id": "T1190", "technique": "SSRF服务端请求伪造"},
    "xxe":                   {"soc_category": "01", "soc_name": "Web应用攻击", "mitre_id": "T1190", "technique": "XXE外部实体注入"},
    "spring_spel":           {"soc_category": "01", "soc_name": "Web应用攻击", "mitre_id": "T1190", "technique": "Spring SpEL注入"},
    "xss":                   {"soc_category": "01", "soc_name": "Web应用攻击", "mitre_id": "T1190", "technique": "XSS跨站脚本"},
    "log4shell":             {"soc_category": "04", "soc_name": "漏洞利用",   "mitre_id": "T1068", "technique": "Log4Shell远程代码执行"},
    "deserialization":       {"soc_category": "04", "soc_name": "漏洞利用",   "mitre_id": "T1068", "technique": "反序列化漏洞"},
    "confluence_ognl":       {"soc_category": "04", "soc_name": "漏洞利用",   "mitre_id": "T1068", "technique": "Confluence OGNL注入"},
    "druid":                 {"soc_category": "04", "soc_name": "漏洞利用",   "mitre_id": "T1068", "technique": "Druid漏洞利用"},
    "rce_command_injection": {"soc_category": "11", "soc_name": "命令执行",   "mitre_id": "T1059", "technique": "命令注入"},
    "webshell_upload":       {"soc_category": "11", "soc_name": "命令执行",   "mitre_id": "T1059", "technique": "Webshell上传"},
    "file_read_traversal":   {"soc_category": "13", "soc_name": "信息泄露",   "mitre_id": "T1552", "technique": "路径遍历/文件读取"},
    "dns_tunneling":         {"soc_category": "08", "soc_name": "隧道通信",   "mitre_id": "T1572", "technique": "DNS隧道"},
    "c2_callback":           {"soc_category": "05", "soc_name": "恶意通信C2", "mitre_id": "T1071", "technique": "C2回调通信"},
    "suspicious_tls_sni":    {"soc_category": "05", "soc_name": "恶意通信C2", "mitre_id": "T1071", "technique": "可疑TLS SNI"},
}


class AlertAnalyzer:
    """告警分析器 - 5 阶段 Chain 编排"""

    def __init__(self):
        # 从 DB 读取 LLM 配置（由系统设置页面管理）
        from .routers.llm_config import get_llm_config_from_db
        llm_cfg = get_llm_config_from_db()

        if not llm_cfg.get("base_url"):
            logger.warning("LLM 未配置，请在系统设置 > 集成配置中配置 LLM 模型")

        # api_key 为空时传一个占位值，ChatOpenAI 要求非空
        api_key = llm_cfg.get("api_key", "") or "not-needed"

        self.llm = ChatOpenAI(
            api_key=api_key,
            base_url=llm_cfg.get("base_url", ""),
            model=llm_cfg.get("model", ""),
            temperature=llm_cfg.get("temperature", 0.1),
            max_tokens=llm_cfg.get("max_tokens", 8000),
            max_retries=0,
            timeout=llm_cfg.get("timeout", 60),
            # Qwen3 系列默认开启思考模式，会输出 <think> 块消耗 token 导致 JSON 截断
            model_kwargs={"extra_body": {"enable_thinking": False}},
        )
        self.model_name = llm_cfg.get("model", "未配置")

        # 初始化各阶段 Chain
        self.triage_chain = create_triage_chain(self.llm)
        self.analysis_chain = create_analysis_chain(self.llm)
        self.unalerted_chain = create_unalerted_analysis_chain(self.llm)

        # 初始化知识检索
        cfg = Config()
        self.knowledge_retriever = create_knowledge_retriever(cfg.knowledge_dir)

        # 初始化规则生成 Chain 和规则写入器
        suricata_cfg = cfg.suricata
        self.rule_gen_enabled = suricata_cfg.get("enabled", False)
        self.rule_generator = None
        self.rule_writer = None
        # 记录已生成过规则的 signature_id，避免同一签名重复生成
        self._rule_generated_sids = set()
        # 记录已处理的漏报攻击（community_id + url + attack_types），避免同会话多告警重复写入
        self._processed_unalerted = set()
        if self.rule_gen_enabled:
            self.rule_generator = create_rule_generator_chain(self.llm)
            try:
                from .suricata.rule_writer import RuleWriter
                self.rule_writer = RuleWriter(
                    rules_file=suricata_cfg["rules_file"],
                    suricata_container=suricata_cfg.get("suricata_container", "suricata"),
                )
            except Exception as e:
                logger.warning("RuleWriter 初始化失败，规则生成功能禁用: %s", e)
                self.rule_gen_enabled = False

        # 后台热加载线程：定时检查 local.rules 修改时间，有变化则热加载
        self._rules_dirty = False
        self._reload_thread = None
        if self.rule_gen_enabled:
            self._start_reload_thread()

        logger.info("AI 分析器已初始化 (6阶段Chain)，模型: %s，规则生成: %s",
                     self.model_name, "启用" if self.rule_gen_enabled else "禁用")

    def _start_reload_thread(self):
        """启动后台热加载线程，每 30 秒检查一次"""
        def reload_loop():
            last_mtime = 0
            try:
                last_mtime = os.path.getmtime(self.rule_writer.rules_file)
            except Exception:
                pass
            while True:
                time.sleep(30)
                try:
                    current_mtime = os.path.getmtime(self.rule_writer.rules_file)
                    if current_mtime > last_mtime:
                        last_mtime = current_mtime
                        logger.info("检测到 local.rules 变更，后台热加载")
                        self.rule_writer.reload_suricata()
                except Exception as e:
                    logger.debug("后台热加载检查失败: %s", e)

        t = threading.Thread(target=reload_loop, daemon=True, name="rule-reloader")
        t.start()
        self._reload_thread = t
        logger.info("后台规则热加载线程已启动 (30s 检查间隔)")

    def analyze(self, alert: dict, related_logs: list = None) -> dict:
        """执行 5 阶段分析流水线

        Args:
            alert: 主告警事件（Logstash 推送或 ES 查询）
            related_logs: 外部预查的关联日志（可选，None 则由 Triage 决定是否查询）

        Returns:
            分析结果 dict
        """
        t_total = time.time()

        # === Stage 1: 告警标准化 ===
        logger.info("=== Stage 1: 告警标准化 ===")
        ctx = normalize_chain.invoke(alert)
        logger.info("标准化完成: %s (severity=%d, community_id=%s)",
                     ctx.signature, ctx.severity, ctx.community_id[:20])

        # === Stage 2: 告警研判 ===
        # severity >= 2 的告警直接查关联日志，跳过 Triage LLM 调用，节省 token
        if ctx.severity >= 2:
            logger.info("=== Stage 2: 跳过 Triage (severity=%d >= 2) ===", ctx.severity)
            triage = TriageResult(
                need_session_query=True,
                need_history_query=(ctx.severity >= 3),
                risk="high" if ctx.severity >= 2 else "medium",
                triage_reason=f"severity={ctx.severity}，跳过 Triage 直接查询关联日志",
            )
        else:
            logger.info("=== Stage 2: 告警研判 (Triage) ===")
            triage_input = {
                "alert_summary": ctx.to_summary(),
                "soc_category": ctx.soc_category,
                "soc_name": ctx.soc_name,
                "mitre_id": ctx.mitre_id,
                "attack_stage": ctx.attack_stage,
            }
            try:
                t0 = time.time()
                triage = self.triage_chain(triage_input)
                logger.info("研判完成 (%.1fs): risk=%s, need_session=%s, need_history=%s",
                            time.time() - t0,
                            triage.risk,
                            triage.need_session_query,
                            triage.need_history_query)
            except Exception as e:
                logger.warning("研判 Chain 失败，使用默认值: %s", e)
                triage = TriageResult(
                    need_session_query=True,
                    need_history_query=False,
                    risk="medium",
                    triage_reason=f"研判失败，使用默认策略: {e}",
                )

        # === Stage 3: 动态关联查询 ===
        logger.info("=== Stage 3: 动态关联查询 ===")
        if related_logs is None:
            # 外部未预查，由 Triage 决定是否查询
            related_logs = []
            if triage.need_session_query and ctx.community_id:
                try:
                    es = ESClient()
                    related_logs = es.query_related_logs(
                        community_id=ctx.community_id,
                        src_ip=ctx.src_ip,
                        dst_ip=ctx.dst_ip,
                        timestamp=ctx.timestamp,
                    )
                    logger.info("关联日志查询: %d 条 (community_id=%s)",
                                len(related_logs), ctx.community_id[:20])
                except Exception as e:
                    logger.warning("关联日志查询失败: %s", e)

            if triage.need_history_query and ctx.src_ip:
                try:
                    es = ESClient()
                    history = es.query_src_ip_history(
                        ctx.src_ip, dst_ip=ctx.dst_ip
                    )
                    logger.info("源IP历史查询: %d 条 (src_ip=%s)", len(history), ctx.src_ip)
                    # 历史记录追加到关联日志
                    related_logs.extend(history)
                except Exception as e:
                    logger.warning("源IP历史查询失败: %s", e)
        else:
            logger.info("使用外部传入的关联日志: %d 条", len(related_logs))

        # 补充 HTTP 上下文：从关联日志的 http 事件中查找实际触发告警的 URL 和响应数据
        if related_logs:
            ctx = self._enrich_http_context(ctx, related_logs)

        # === Stage 4: 知识增强 (RAG) ===
        logger.info("=== Stage 4: 知识增强 (RAG) ===")
        try:
            knowledge = self.knowledge_retriever.invoke(ctx)
            logger.info("知识检索完成: %d 字符", len(knowledge))
        except Exception as e:
            logger.warning("知识检索失败: %s", e)
            knowledge = "无可用知识"

        # === Stage 5: 最终分析 ===
        logger.info("=== Stage 5: 最终分析 ===")
        analysis_input = {
            "alert_summary": ctx.to_summary(),
            "soc_category": ctx.soc_category,
            "soc_name": ctx.soc_name,
            "mitre_id": ctx.mitre_id,
            "attack_stage": ctx.attack_stage,
            "risk": triage.risk,
            "related_count": len(related_logs),
            "related_logs": format_logs(related_logs) if related_logs else "无关联日志",
            "knowledge": knowledge,
        }
        try:
            t0 = time.time()
            result = self.analysis_chain(analysis_input)
            logger.info("分析完成 (%.1fs): 判定=%s, 置信度=%s",
                        time.time() - t0,
                        result.threat_verdict,
                        result.confidence)
            analysis = result.model_dump()
        except Exception as e:
            logger.error("分析 Chain 失败: %s", e, exc_info=True)
            analysis = self._fallback_result(ctx, str(e))

        # 补充元数据
        self._enrich_metadata(analysis, ctx, alert, related_logs)

        # 标记分析来源
        analysis["analysis_source"] = "alert_triage"

        # Stage 6 规则生成 + 漏报处理 放到后台线程，不阻塞主记录写入 ES
        analysis["_bg_context"] = {
            "ctx": ctx,
            "related_logs": related_logs,
        }

        logger.info("=== 主分析完成 (%.1fs)，规则生成和漏报处理转后台 ===", time.time() - t_total)
        return analysis

    def _generate_main_rule(self, ctx: AlertContext, analysis: dict,
                            related_logs: list) -> dict | None:
        """Stage 6 主路径: 基于当前告警 payload 生成 Suricata 规则

        触发条件:
        1. 规则生成功能已启用
        2. AI 判定为"确认威胁"
        3. 置信度 >= 0.7
        4. 有可用 payload

        漏报攻击的规则生成在 _process_unalerted_attacks 中独立处理。

        Returns:
            规则生成结果 dict 或 None（未触发）
        """
        if not self.rule_gen_enabled or not self.rule_writer:
            return None

        if analysis.get("threat_verdict") != "确认威胁":
            return None

        if ctx.signature_id and ctx.signature_id in self._rule_generated_sids:
            logger.info("Stage 6: signature_id=%d 已生成过规则，跳过", ctx.signature_id)
            return None

        confidence = analysis.get("confidence", 0)
        if confidence < 0.7:
            logger.info("Stage 6: 置信度 %.2f < 0.7，跳过规则生成", confidence)
            return None

        if not ctx.payload:
            return None

        logger.info("=== Stage 6: 规则生成（主路径）===")
        result = self._generate_single_rule(
            ctx, analysis, related_logs,
            payload=ctx.payload[:2000],
            current_signature=ctx.signature,
        )
        if result:
            # 记录已生成规则的 signature_id
            if ctx.signature_id:
                self._rule_generated_sids.add(ctx.signature_id)
        return result

    def _process_unalerted_attacks(self, ctx: AlertContext, analysis: dict,
                                    related_logs: list) -> list[dict]:
        """处理漏报攻击：语义检测 + 轻量 LLM 研判 + 批量规则生成

        对关联日志中未触发 alert 的攻击事件，批量调用轻量 LLM 补全研判字段，
        为每个漏报事件构建独立的分析记录（写入 soc-ai-*）。

        规则生成策略：
        - 漏报攻击的规则生成批量处理，单次 LLM 调用生成所有规则
        - 规则写入后只热加载一次，避免 N 次热加载超时阻塞主流程

        Returns:
            漏报攻击分析记录列表，空列表表示无漏报
        """
        if not related_logs:
            return []

        unalerted = find_unalerted_attacks(related_logs)
        if not unalerted:
            return []

        # 去重：同一 community_id + url + attack_types 的漏报事件只处理一次
        # 避免同会话多告警重复发现同一批漏报攻击
        new_unalerted = []
        for item in unalerted:
            dedup_key = (
                ctx.community_id,
                item["url"],
                tuple(sorted(item["attack_types"])),
            )
            if dedup_key in self._processed_unalerted:
                continue
            self._processed_unalerted.add(dedup_key)
            new_unalerted.append(item)

        if not new_unalerted:
            logger.info("漏报攻击 %d 条均已处理过，跳过", len(unalerted))
            return []

        if len(new_unalerted) < len(unalerted):
            logger.info("漏报攻击去重: %d → %d 条", len(unalerted), len(new_unalerted))
        unalerted = new_unalerted

        logger.info("发现 %d 个漏报攻击事件，启动轻量分析", len(unalerted))

        # 批量轻量 LLM 研判（单次调用处理所有漏报事件）
        llm_results = []
        try:
            t0 = time.time()
            unalerted_list_text = "\n".join(
                f"{i + 1}. 攻击类型: {', '.join(item['attack_types'])} | "
                f"事件: {item['event_type']} | URL: {item['url']} | "
                f"Payload: {item['payload'][:200]}"
                + (f" | 响应状态码: {item['http_status']}" if item.get('http_status') else "")
                + (f" | 响应体: {item['response_body'][:500]}" if item.get('response_body') else "")
                for i, item in enumerate(unalerted)
            )
            llm_results = self.unalerted_chain({
                "main_alert_summary": ctx.to_summary(),
                "count": len(unalerted),
                "unalerted_list": unalerted_list_text,
            })
            logger.info("漏报轻量分析完成 (%.1fs): %d 条结果",
                        time.time() - t0, len(llm_results))
        except Exception as e:
            logger.warning("漏报轻量分析失败，使用默认值: %s", e)

        # 为每个漏报事件构建独立分析记录（不含规则生成，避免阻塞）
        records = []
        rules_to_write = []
        for i, item in enumerate(unalerted):
            llm_data = llm_results[i] if i < len(llm_results) else {}
            record = self._build_unalerted_analysis(ctx, item, llm_data, related_logs)
            if record:
                records.append(record)
                # 收集需要生成规则的漏报事件
                if self.rule_gen_enabled and self.rule_writer:
                    rules_to_write.append((i, item, record))

        # 批量规则生成：每个漏报事件生成规则，但规则写入后只热加载一次
        if rules_to_write:
            self._batch_generate_unalerted_rules(ctx, analysis, related_logs, rules_to_write, records)

        return records

    def _batch_generate_unalerted_rules(self, ctx: AlertContext, analysis: dict,
                                         related_logs: list,
                                         rules_to_write: list,
                                         records: list[dict]):
        """批量生成漏报攻击规则

        为每个漏报事件生成规则（串行 LLM 调用），但规则写入文件后
        只执行一次热加载，避免 N 次 30s 超时阻塞主流程。

        Args:
            rules_to_write: [(index, item, record), ...] 需要生成规则的漏报事件
            records: 漏报记录列表，生成的规则会挂到对应记录上
        """
        rules_written = []
        records_to_update = []  # (record, result) 待回写 reloaded 状态
        for idx, item, record in rules_to_write:
            try:
                t0 = time.time()
                rule_input = {
                    "alert_summary": ctx.to_summary(),
                    "threat_verdict": "确认威胁",
                    "attack_technique": record.get("attack_technique", ""),
                    "confidence": record.get("confidence", 0.7),
                    "payload": (item["payload"] or item["url"])[:2000],
                    "related_logs": format_logs(related_logs) if related_logs else "无关联日志",
                    "current_signature": "（无 - 漏报攻击）",
                    "unalerted_attack_types": ", ".join(item["attack_types"]),
                    "unalerted_url": item["url"],
                }

                gen_result = self.rule_generator(rule_input)
                logger.info("漏报规则生成 (%d/%d, %.1fs): fp_risk=%s",
                            idx + 1, len(rules_to_write),
                            time.time() - t0, gen_result.fp_risk)

                result = {
                    "rule": gen_result.rule,
                    "fp_risk": gen_result.fp_risk,
                    "should_write": gen_result.should_write,
                    "reason": gen_result.reason,
                    "written": False,
                    "reloaded": False,
                    "source": "unalerted",
                    "unalerted_attack_types": item["attack_types"],
                    "unalerted_url": item["url"],
                }

                # 仅低误报规则写入文件（批量写入后统一热加载一次）
                if gen_result.should_write and gen_result.fp_risk == "low":
                    write_result = self.rule_writer.write_only(gen_result.rule)
                    result["written"] = write_result["written"]
                    result["message"] = write_result["message"]
                    if write_result["written"]:
                        rules_written.append(gen_result.rule)
                        records_to_update.append((record, result))
                else:
                    result["message"] = f"误报风险为 {gen_result.fp_risk}，未写入"

                record["generated_rule"] = result

            except Exception as e:
                logger.error("漏报规则生成失败: %s", e, exc_info=True)

        # 批量写入完成后统一热加载一次，并回写 reloaded 状态
        if rules_written:
            reload_result = self.rule_writer.reload_rules()
            reloaded = reload_result["reloaded"]
            logger.info("漏报规则批量写入 %d 条，热加载: %s", len(rules_written), reload_result["message"])
            # 回写 reloaded 状态到每条记录
            for record, result in records_to_update:
                result["reloaded"] = reloaded
                result["message"] = f"规则已写入，热加载{'成功' if reloaded else '失败'}"
                record["generated_rule"] = result

    def _build_unalerted_analysis(self, ctx: AlertContext, item: dict,
                                   llm_data: dict, related_logs: list) -> dict | None:
        """构建单条漏报攻击的分析记录

        语义检测填充固定字段，轻量 LLM 填充研判字段，字段结构与主告警记录一致。

        Args:
            ctx: 主告警上下文（复用网络五元组等信息）
            item: find_unalerted_attacks 返回的单个漏报事件
            llm_data: 轻量 LLM 输出的研判字段
            related_logs: 关联日志（用于规则生成上下文）
        """
        attack_type = item["attack_types"][0] if item["attack_types"] else "unknown"
        mapping = ATTACK_TYPE_SOC_MAPPING.get(attack_type, {
            "soc_category": "", "soc_name": "未知攻击",
            "mitre_id": "", "technique": attack_type,
        })

        record = {
            "analysis_source": "semantic_unalerted",
            "threat_verdict": "确认威胁",
            "attack_technique": mapping["technique"],
            "attack_stage": ctx.attack_stage,
            "impact_scope": llm_data.get("impact_scope", "N/A"),
            "confidence": llm_data.get("confidence", 0.7),
            "attack_chain": llm_data.get("attack_chain", "N/A"),
            "handling_suggestion": llm_data.get("handling_suggestion", "N/A"),
            "attack_result": llm_data.get("attack_result", "未知"),
            "reasoning": llm_data.get(
                "reasoning", f"语义检测命中: {', '.join(item['attack_types'])}"
            ),
            # 元数据
            "model": self.model_name,
            "soc_category": mapping["soc_category"],
            "soc_name": mapping["soc_name"],
            "mitre_id": mapping["mitre_id"],
            "attack_stage_tag": ctx.attack_stage,
            # 复用主告警的五元组（同一会话）
            "source_ip": ctx.src_ip,
            "source_port": ctx.src_port,
            "destination_ip": ctx.dst_ip,
            "destination_port": ctx.dst_port,
            "protocol": ctx.protocol,
            "community_id": ctx.community_id,
            # 漏报事件无原始告警签名
            "alert_signature": f"语义检测:{mapping['technique']}",
            "alert_signature_id": 0,
            "alert_category": "语义检测",
            "alert_severity": 2,
            "alert_timestamp": item["timestamp"],
            "related_log_count": len(related_logs),
            # source_alert_id 指向漏报攻击自身的原始日志文档（soc-*），
            # 而非触发分析的主告警（triggered_by_alert 已记录主AI记录）
            "source_alert_id": item.get("log_id", ""),
            "source_alert_index": item.get("log_index", ""),
            "payload": (item["payload"] or item["url"] or "")[:4000],
        }

        # 协议特定字段
        if item["event_type"] == "http":
            record["http_url"] = item["url"]
            if item.get("http_status"):
                record["http_status"] = item["http_status"]
            if item.get("response_body"):
                record["response_body"] = item["response_body"][:4000]
        elif item["event_type"] == "tls":
            record["tls_sni"] = item["payload"]

        # 规则生成在 _batch_generate_unalerted_rules 中批量处理

        return record

    def _generate_single_rule(self, ctx: AlertContext, analysis: dict,
                              related_logs: list, payload: str,
                              current_signature: str,
                              unalerted_info: dict = None) -> dict | None:
        """生成单条 Suricata 规则

        Args:
            unalerted_info: 反向触发时的漏报攻击信息（主路径为 None）
        """
        try:
            t0 = time.time()
            rule_input = {
                "alert_summary": ctx.to_summary(),
                "threat_verdict": analysis.get("threat_verdict", ""),
                "attack_technique": analysis.get("attack_technique", ""),
                "confidence": analysis.get("confidence", 0),
                "payload": payload,
                "related_logs": format_logs(related_logs) if related_logs else "无关联日志",
                "current_signature": current_signature,
            }

            if unalerted_info:
                rule_input["unalerted_attack_types"] = ", ".join(unalerted_info["attack_types"])
                rule_input["unalerted_url"] = unalerted_info["url"]

            gen_result = self.rule_generator(rule_input)
            logger.info("规则生成完成 (%.1fs): fp_risk=%s, should_write=%s",
                        time.time() - t0, gen_result.fp_risk, gen_result.should_write)

            result = {
                "rule": gen_result.rule,
                "fp_risk": gen_result.fp_risk,
                "should_write": gen_result.should_write,
                "reason": gen_result.reason,
                "written": False,
                "reloaded": False,
                "source": "unalerted" if unalerted_info else "main",
            }
            if unalerted_info:
                result["unalerted_attack_types"] = unalerted_info["attack_types"]
                result["unalerted_url"] = unalerted_info["url"]

            # 仅低误报规则写入文件并同步热加载
            if gen_result.should_write and gen_result.fp_risk == "low":
                write_result = self.rule_writer.write_and_reload(gen_result.rule)
                result["written"] = write_result["written"]
                result["reloaded"] = write_result["reloaded"]
                result["message"] = write_result["message"]
                logger.info("规则写入+热加载: %s", write_result["message"])
            else:
                result["message"] = f"误报风险为 {gen_result.fp_risk}，未写入"
                logger.info("规则未写入: %s", result["message"])

            return result

        except Exception as e:
            logger.error("规则生成失败: %s", e, exc_info=True)
            return {"error": str(e), "written": False}

    def _enrich_http_context(self, ctx: AlertContext,
                             related_logs: list) -> AlertContext:
        """从关联日志中补充 HTTP 上下文

        Suricata alert 事件在 HTTP keep-alive 多事务场景下，
        payload_printable 可能只包含流的第一个 HTTP 事务，
        而实际触发告警的是后续事务（不同 tx_id）。
        此方法从关联的 http 事件中查找实际触发告警的 URL。

        策略：优先匹配 signature 关键词到 http 事件的 URL，
        找不到则用最后一个 http 事件的 URL（最新事务）。
        """
        # 收集同会话的 http 事件 URL
        http_events = []
        for log in related_logs:
            eve = log.get("suricata", {}).get("eve", {})
            if eve.get("event_type") != "http":
                continue
            http = eve.get("http", {})
            url = http.get("url", "")
            method = http.get("http_method", "")
            host = http.get("hostname", "")
            if url:
                http_events.append({
                    "url": url,
                    "method": method,
                    "host": host,
                    "timestamp": log.get("@timestamp", ""),
                    "status": http.get("status", 0),
                    "response_body": decode_http_body(http, "http_response_body") or eve.get("http", {}).get("http_response_body_printable", ""),
                })

            # Zeek http 日志
            if not url and log.get("event", {}).get("dataset") == "zeek.http":
                url = log.get("url", {}).get("original", "")
                host = log.get("url", {}).get("domain", "")
                if url:
                    http_events.append({
                        "url": url,
                        "method": log.get("http", {}).get("request", {}).get("method", ""),
                        "host": host,
                        "timestamp": log.get("@timestamp", ""),
                        "status": log.get("http", {}).get("response", {}).get("status_code", 0) or 0,
                        "response_body": "",
                    })

        if not http_events:
            return ctx

        # 从 signature 中提取关键词，尝试匹配到 http 事件的 URL
        sig_lower = ctx.signature.lower()
        matched_url = ""
        matched_host = ""
        matched_method = ""
        matched_status = 0
        matched_response_body = ""

        for event in http_events:
            url_lower = event["url"].lower()
            # 取 signature 中的关键词片段（如 "cat /etc/passwd" → "cat" + "passwd"）
            # 用 URL 解码后的 URL 匹配
            try:
                from urllib.parse import unquote
                url_decoded = unquote(url_lower)
            except Exception:
                url_decoded = url_lower

            # 检查 signature 中的关键内容是否出现在 URL 中
            # 提取 signature 中长度 > 3 的词
            sig_words = [w for w in re.findall(r'[a-zA-Z_/.]+', sig_lower) if len(w) > 3]
            match_count = sum(1 for w in sig_words if w in url_decoded)
            if match_count >= 2:  # 至少匹配 2 个关键词
                matched_url = event["url"]
                matched_host = event["host"]
                matched_method = event["method"]
                matched_status = event.get("status", 0)
                matched_response_body = event.get("response_body", "")
                logger.info("HTTP 上下文补充: signature 匹配到 URL %s", matched_url[:80])
                break

        # 未匹配到 signature 关键词，使用最后一个 http 事件（最新事务）
        if not matched_url and http_events:
            last = http_events[-1]
            matched_url = last["url"]
            matched_host = last["host"]
            matched_method = last["method"]
            matched_status = last.get("status", 0)
            matched_response_body = last.get("response_body", "")
            logger.info("HTTP 上下文补充: 使用最新 http 事件 URL %s", matched_url[:80])

        if matched_url:
            # 仅当告警自身缺少 HTTP 请求上下文时才补充，避免覆盖
            if not ctx.http_url:
                ctx.http_url = matched_url
            if not ctx.http_host and matched_host:
                ctx.http_host = matched_host
            if not ctx.http_method and matched_method:
                ctx.http_method = matched_method
            # 响应侧字段始终提取
            if matched_status:
                ctx.http_status = matched_status
            if matched_response_body:
                ctx.response_body = matched_response_body
                # 重建 payload，包含实际触发告警的请求行
                request_line = f"{matched_method} {matched_host}{matched_url} HTTP/1.1"
                if ctx.payload:
                    # 追加到现有 payload 前面
                    ctx.payload = f"[实际触发告警的请求]\n{request_line}\n\n[alert payload（可能为流首事务）]\n{ctx.payload}"
                else:
                    ctx.payload = request_line

        return ctx

    def _enrich_metadata(self, analysis: dict, ctx: AlertContext,
                         alert: dict, related_logs: list):
        """补充元数据到分析结果"""
        analysis["model"] = self.model_name
        analysis["soc_category"] = ctx.soc_category
        analysis["soc_name"] = ctx.soc_name
        analysis["mitre_id"] = ctx.mitre_id
        analysis["attack_stage_tag"] = ctx.attack_stage

        # 五元组
        analysis["source_ip"] = ctx.src_ip
        analysis["source_port"] = ctx.src_port
        analysis["destination_ip"] = ctx.dst_ip
        analysis["destination_port"] = ctx.dst_port
        analysis["protocol"] = ctx.protocol
        analysis["community_id"] = ctx.community_id

        # 告警信息
        analysis["alert_signature"] = ctx.signature
        analysis["alert_signature_id"] = ctx.signature_id
        analysis["alert_category"] = ctx.category
        analysis["alert_severity"] = ctx.severity
        analysis["alert_timestamp"] = ctx.timestamp
        analysis["related_log_count"] = len(related_logs)

        # 原始告警 ES 文档 ID
        # Logstash 推送的告警不带 _id，需要多级 fallback：
        # 1. 告警自身带的 _id（手动触发分析时）
        # 2. 从关联日志中查找同 signature_id 的文档（按时间最接近排序）
        # 3. 回查 ES 按 community_id + signature_id + timestamp 精确查找
        # 4. ES 宽松回查 community_id + signature_id（不限时间）
        source_alert_id = alert.get("_id", "")
        source_alert_index = alert.get("_index", "")

        # 2. 从关联日志中按 signature_id 匹配（时间最接近的优先）
        if not source_alert_id and related_logs:
            candidates = []
            for log in related_logs:
                log_eve = log.get("suricata", {}).get("eve", {})
                log_alert = log_eve.get("alert", {})
                if log_alert.get("signature_id") == ctx.signature_id:
                    candidates.append(log)
            if candidates:
                # 按时间戳与当前告警的差值排序，取最接近的
                from datetime import datetime
                try:
                    target_ts = datetime.fromisoformat(ctx.timestamp.replace("Z", "+00:00"))
                except Exception:
                    target_ts = None

                def time_diff(log):
                    if not target_ts:
                        return 0
                    try:
                        log_ts = datetime.fromisoformat(log.get("@timestamp", "").replace("Z", "+00:00"))
                        return abs((log_ts - target_ts).total_seconds())
                    except Exception:
                        return float('inf')

                candidates.sort(key=time_diff)
                source_alert_id = candidates[0].get("_id", "")
                source_alert_index = candidates[0].get("_index", "")
                logger.info("从关联日志匹配到原始告警: _id=%s (候选 %d 条)", source_alert_id, len(candidates))

        # 3. ES 回查
        if not source_alert_id:
            try:
                es = ESClient()
                source_alert_id, source_alert_index = es.find_original_alert(
                    ctx.community_id, ctx.signature_id, ctx.timestamp
                )
            except Exception as e:
                logger.warning("回查原始告警 _id 失败: %s", e)
        analysis["source_alert_id"] = source_alert_id
        analysis["source_alert_index"] = source_alert_index

        # HTTP/TLS
        if ctx.http_method:
            analysis["http_method"] = ctx.http_method
            analysis["http_url"] = ctx.http_url
            analysis["http_host"] = ctx.http_host
            analysis["http_user_agent"] = ctx.http_user_agent
        if ctx.tls_sni:
            analysis["tls_sni"] = ctx.tls_sni
        if ctx.payload:
            analysis["payload"] = ctx.payload[:4000]
        if ctx.http_status:
            analysis["http_status"] = ctx.http_status
        if ctx.response_body:
            analysis["response_body"] = ctx.response_body[:4000]

    def _fallback_result(self, ctx: AlertContext, error: str) -> dict:
        """分析失败降级结果"""
        return {
            "threat_verdict": "可疑",
            "confidence": 0.3,
            "attack_result": "未知",
            "attack_technique": "N/A（分析失败）",
            "attack_stage": ctx.attack_stage,
            "impact_scope": "N/A",
            "attack_chain": "N/A",
            "handling_suggestion": "AI 分析失败，建议人工审查此告警",
            "reasoning": f"分析失败: {error}",
            "model": self.model_name,
            "soc_category": ctx.soc_category,
            "soc_name": ctx.soc_name,
            "mitre_id": ctx.mitre_id,
            "attack_stage_tag": ctx.attack_stage,
            "source_ip": ctx.src_ip,
            "source_port": ctx.src_port,
            "destination_ip": ctx.dst_ip,
            "destination_port": ctx.dst_port,
            "protocol": ctx.protocol,
            "community_id": ctx.community_id,
            "alert_signature": ctx.signature,
            "alert_signature_id": ctx.signature_id,
            "alert_category": ctx.category,
            "alert_severity": ctx.severity,
            "alert_timestamp": ctx.timestamp,
            "source_alert_id": "",
            "source_alert_index": "",
            "related_log_count": 0,
            "error": error,
        }
