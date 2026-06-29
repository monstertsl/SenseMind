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
from langchain_openai import ChatOpenAI
from .config import Config
from .models import AlertContext, TriageResult
from .chains.normalize import normalize_chain
from .chains.triage import create_triage_chain
from .chains.analysis import create_analysis_chain
from .chains.rule_generator import create_rule_generator_chain
from .tools.es_tools import format_logs
from .knowledge.rag import create_knowledge_retriever
from .es_client import ESClient
from .attack_detector import find_unalerted_attacks
from .threat_intel import ThreatIntelClient

logger = logging.getLogger(__name__)


class AlertAnalyzer:
    """告警分析器 - 5 阶段 Chain 编排"""

    def __init__(self):
        cfg = Config()
        llm_cfg = cfg.llm

        self.llm = ChatOpenAI(
            api_key=llm_cfg["api_key"],
            base_url=llm_cfg["base_url"],
            model=llm_cfg["model"],
            temperature=llm_cfg.get("temperature", 0.1),
            max_tokens=llm_cfg.get("max_tokens", 2000),
            max_retries=0,
            timeout=llm_cfg.get("timeout", 60),
            # Qwen3 系列默认开启思考模式，会输出 <think> 块消耗 token 导致 JSON 截断
            model_kwargs={"extra_body": {"enable_thinking": False}},
        )
        self.model_name = llm_cfg["model"]

        # 初始化各阶段 Chain
        self.triage_chain = create_triage_chain(self.llm)
        self.analysis_chain = create_analysis_chain(self.llm)

        # 初始化知识检索
        self.knowledge_retriever = create_knowledge_retriever(cfg.knowledge_dir)

        # 初始化规则生成 Chain 和规则写入器
        suricata_cfg = cfg.suricata
        self.rule_gen_enabled = suricata_cfg.get("enabled", False)
        self.rule_generator = None
        self.rule_writer = None
        # 记录已生成过规则的 signature_id，避免同一签名重复生成
        self._rule_generated_sids = set()
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

        logger.info("AI 分析器已初始化 (6阶段Chain)，模型: %s，规则生成: %s",
                     self.model_name, "启用" if self.rule_gen_enabled else "禁用")

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
            logger.info("研判完成 (%.1fs): risk=%s, need_session=%s, need_history=%s, need_threat_intel=%s",
                        time.time() - t0,
                        triage.risk,
                        triage.need_session_query,
                        triage.need_history_query,
                        triage.need_threat_intel)
        except Exception as e:
            logger.warning("研判 Chain 失败，使用默认值: %s", e)
            triage = TriageResult(
                need_session_query=True,
                need_history_query=False,
                need_threat_intel=False,
                risk="medium",
                triage_reason=f"研判失败，使用默认策略: {e}",
            )

        # === Stage 3: 动态关联查询 ===
        logger.info("=== Stage 3: 动态关联查询 ===")
        threat_intel_text = "无威胁情报"
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

            # 威胁情报查询
            if triage.need_threat_intel:
                try:
                    ti = ThreatIntelClient()
                    threat_intel_text = ti.query_for_alert(
                        src_ip=ctx.src_ip,
                        dst_ip=ctx.dst_ip,
                        tls_sni=ctx.tls_sni,
                        http_host=ctx.http_host,
                    )
                    logger.info("威胁情报查询完成: %d 字符", len(threat_intel_text))
                except Exception as e:
                    logger.warning("威胁情报查询失败: %s", e)
        else:
            logger.info("使用外部传入的关联日志: %d 条", len(related_logs))

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
            "threat_intel": threat_intel_text,
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

        # === Stage 6: 规则生成 ===
        rule_result = self._try_generate_rule(ctx, analysis, related_logs)
        if rule_result:
            analysis["generated_rule"] = rule_result

        logger.info("=== 全流程完成 (%.1fs) ===", time.time() - t_total)
        return analysis

    def _try_generate_rule(self, ctx: AlertContext, analysis: dict,
                           related_logs: list) -> dict | None:
        """Stage 6: 确认攻击时，自动生成 Suricata 规则

        触发条件:
        1. 规则生成功能已启用
        2. AI 判定为"确认威胁"
        3. 置信度 >= 0.7
        4. 有可用 payload 或关联日志中有未触发 alert 的攻击事件

        两个生成路径:
        - 主路径: 基于当前告警 payload 生成规则（当前规则可能不够精确）
        - 反向触发: 检查同 community_id 的非 alert 事件，为漏报的攻击生成规则

        Returns:
            规则生成结果 dict 或 list，或 None（未触发）
        """
        if not self.rule_gen_enabled or not self.rule_writer:
            return None

        # 仅对确认威胁的告警生成规则
        if analysis.get("threat_verdict") != "确认威胁":
            return None

        # 按 signature_id 去重：同一告警签名已生成过规则就不再生成
        if ctx.signature_id and ctx.signature_id in self._rule_generated_sids:
            logger.info("Stage 6: signature_id=%d 已生成过规则，跳过", ctx.signature_id)
            return None

        # 置信度门槛
        confidence = analysis.get("confidence", 0)
        if confidence < 0.7:
            logger.info("Stage 6: 置信度 %.2f < 0.7，跳过规则生成", confidence)
            return None

        results = []

        # === 主路径: 基于当前告警生成规则 ===
        if ctx.payload:
            logger.info("=== Stage 6: 规则生成（主路径）===")
            result = self._generate_single_rule(
                ctx, analysis, related_logs,
                payload=ctx.payload[:2000],
                current_signature=ctx.signature,
            )
            if result:
                results.append(result)

        # === 反向触发: 检查关联日志中未触发 alert 的攻击事件 ===
        if related_logs:
            unalerted = find_unalerted_attacks(related_logs)
            if unalerted:
                logger.info("=== Stage 6: 规则生成（反向触发）===")
                logger.info("发现 %d 个未触发告警的攻击事件", len(unalerted))
                for item in unalerted:
                    result = self._generate_single_rule(
                        ctx, analysis, related_logs,
                        payload=item["payload"] or item["url"],
                        current_signature="（无 - 漏报攻击）",
                        unalerted_info=item,
                    )
                    if result:
                        results.append(result)

        if not results:
            return None
        return results[0] if len(results) == 1 else results

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

            # 仅低误报规则写入文件
            if gen_result.should_write and gen_result.fp_risk == "low":
                write_result = self.rule_writer.write_and_reload(gen_result.rule)
                result["written"] = write_result["written"]
                result["reloaded"] = write_result["reloaded"]
                result["message"] = write_result["message"]
                logger.info("规则写入: %s", write_result["message"])
                # 记录已生成规则的 signature_id（仅主路径，非反向触发）
                if not unalerted_info and ctx.signature_id:
                    self._rule_generated_sids.add(ctx.signature_id)
            else:
                result["message"] = f"误报风险为 {gen_result.fp_risk}，未写入"
                logger.info("规则未写入: %s", result["message"])

            return result

        except Exception as e:
            logger.error("规则生成失败: %s", e, exc_info=True)
            return {"error": str(e), "written": False}

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
