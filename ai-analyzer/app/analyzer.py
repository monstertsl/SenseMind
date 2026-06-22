"""AI 分析核心 - 基于 LangChain 确定性链"""

import json
import logging
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from .config import Config
from .prompts import (
    SYSTEM_PROMPT,
    ANALYSIS_PROMPT_TEMPLATE,
    format_alert_summary,
    format_related_logs,
)

logger = logging.getLogger(__name__)


class AlertAnalyzer:
    """告警分析器 - LangChain 确定性链"""

    def __init__(self):
        cfg = Config()
        llm_cfg = cfg.llm

        # 使用 OpenAI 兼容接口（适配OpenAI兼容接口）
        self.llm = ChatOpenAI(
            api_key=llm_cfg["api_key"],
            base_url=llm_cfg["base_url"],
            model=llm_cfg["model"],
            temperature=llm_cfg.get("temperature", 0.1),
            max_tokens=llm_cfg.get("max_tokens", 2000),
        )
        self.model_name = llm_cfg["model"]
        logger.info("AI 分析器已初始化，模型: %s", self.model_name)

    def analyze(self, alert: dict, related_logs: list) -> dict:
        """
        分析告警，返回结构化研判结果

        Args:
            alert: 主告警事件（Logstash 推送或 ES 查询）
            related_logs: 关联日志列表

        Returns:
            分析结果 dict
        """
        soc = alert.get("soc", {})
        alert_summary = format_alert_summary(alert)
        related_str = format_related_logs(related_logs)

        user_prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            alert_summary=alert_summary,
            soc_category=soc.get("category", "N/A"),
            soc_name=soc.get("name", "N/A"),
            mitre_id=soc.get("mitre_id", "N/A"),
            attack_stage=soc.get("stage", "N/A"),
            related_count=len(related_logs),
            related_logs=related_str,
        )

        logger.info("开始调用 LLM 分析，告警签名: %s", alert.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", ""))

        try:
            messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=user_prompt)]
            response = self.llm.invoke(messages)
            result = self._parse_response(response.content, alert, related_logs)
            return result
        except Exception as e:
            logger.error("LLM 分析失败: %s", e, exc_info=True)
            return self._fallback_result(alert, str(e))

    def _parse_response(self, content: str, alert: dict, related_logs: list) -> dict:
        """解析 LLM 返回的 JSON 结果"""
        # 尝试提取 JSON（LLM 可能包裹在 markdown 代码块中）
        text = content.strip()
        if text.startswith("```"):
            # 去掉 markdown 代码块标记
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            analysis = json.loads(text)
        except json.JSONDecodeError:
            # JSON 解析失败，尝试提取花括号内容
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    analysis = json.loads(text[start:end])
                except json.JSONDecodeError:
                    logger.warning("LLM 返回内容无法解析为 JSON: %s", text[:200])
                    return self._fallback_result(alert, "JSON解析失败", raw_response=content)
            else:
                logger.warning("LLM 返回内容无 JSON 结构: %s", text[:200])
                return self._fallback_result(alert, "无JSON结构", raw_response=content)

        # 补充元数据
        soc = alert.get("soc", {})
        eve = alert.get("suricata", {}).get("eve", {})
        alert_info = eve.get("alert", {})
        src = alert.get("source", {})
        dst = alert.get("destination", {})
        http = eve.get("http", {})
        tls = eve.get("tls", {})

        analysis["model"] = self.model_name
        analysis["soc_category"] = soc.get("category", "")
        analysis["soc_name"] = soc.get("name", "")
        analysis["mitre_id"] = soc.get("mitre_id", "")
        analysis["attack_stage_tag"] = soc.get("stage", "")

        # 五元组信息
        analysis["source_ip"] = src.get("ip", "")
        analysis["source_port"] = src.get("port", 0)
        analysis["destination_ip"] = dst.get("ip", "")
        analysis["destination_port"] = dst.get("port", 0)
        analysis["protocol"] = alert.get("network", {}).get("transport", "")
        analysis["community_id"] = alert.get("network", {}).get("community_id", "")

        # 告警信息
        analysis["alert_signature"] = alert_info.get("signature", "")
        analysis["alert_signature_id"] = alert_info.get("signature_id", 0)
        analysis["alert_category"] = alert_info.get("category", "")
        analysis["alert_severity"] = alert_info.get("severity", 0)
        analysis["alert_timestamp"] = alert.get("@timestamp", "")

        # 原始告警 ES 文档 ID（关联原始日志）
        # Logstash 推送时不带 _id，从关联日志中查找同 signature_id 的原始告警
        source_alert_id = alert.get("_id", "")
        source_alert_index = alert.get("_index", "")
        if not source_alert_id and related_logs:
            sig_id = alert_info.get("signature_id", 0)
            alert_ts = alert.get("@timestamp", "")
            for log in related_logs:
                log_eve = log.get("suricata", {}).get("eve", {})
                log_alert = log_eve.get("alert", {})
                if (
                    log_alert.get("signature_id") == sig_id
                    and log.get("@timestamp") == alert_ts
                ):
                    source_alert_id = log.get("_id", "")
                    source_alert_index = log.get("_index", "")
                    break
            # 如果没精确匹配，取第一条关联日志的 _id
            if not source_alert_id:
                source_alert_id = related_logs[0].get("_id", "")
                source_alert_index = related_logs[0].get("_index", "")
        analysis["source_alert_id"] = source_alert_id
        analysis["source_alert_index"] = source_alert_index

        # HTTP/TLS 元数据
        if http:
            analysis["http_method"] = http.get("http_method", "")
            analysis["http_url"] = http.get("url", "")
            analysis["http_host"] = http.get("hostname", "")
            analysis["http_user_agent"] = http.get("http_user_agent", "")
        if tls:
            analysis["tls_sni"] = tls.get("sni", "")

        # 攻击 payload（截断到 4000 字符，供人工研判）
        payload = eve.get("payload_printable", "")
        if payload:
            analysis["payload"] = payload[:4000]

        # 关联日志数
        analysis["related_log_count"] = len(related_logs)

        logger.info(
            "分析完成: 判定=%s, 置信度=%s",
            analysis.get("threat_verdict", "N/A"),
            analysis.get("confidence", "N/A"),
        )
        return analysis

    def _fallback_result(self, alert: dict, error: str, raw_response: str = "") -> dict:
        """LLM 失败时的降级结果"""
        soc = alert.get("soc", {})
        eve = alert.get("suricata", {}).get("eve", {})
        alert_info = eve.get("alert", {})
        src = alert.get("source", {})
        dst = alert.get("destination", {})
        http = eve.get("http", {})
        payload = eve.get("payload_printable", "")
        result = {
            "threat_verdict": "可疑",
            "confidence": 0.3,
            "attack_result": "未知",
            "attack_technique": "N/A（分析失败）",
            "attack_stage": soc.get("stage", "N/A"),
            "impact_scope": "N/A",
            "attack_chain": "N/A",
            "handling_suggestion": "AI 分析失败，建议人工审查此告警",
            "reasoning": f"分析失败: {error}",
            "model": self.model_name,
            "soc_category": soc.get("category", ""),
            "soc_name": soc.get("name", ""),
            "mitre_id": soc.get("mitre_id", ""),
            "attack_stage_tag": soc.get("stage", ""),
            "source_ip": src.get("ip", ""),
            "source_port": src.get("port", 0),
            "destination_ip": dst.get("ip", ""),
            "destination_port": dst.get("port", 0),
            "protocol": alert.get("network", {}).get("transport", ""),
            "community_id": alert.get("network", {}).get("community_id", ""),
            "alert_signature": alert_info.get("signature", ""),
            "alert_signature_id": alert_info.get("signature_id", 0),
            "alert_category": alert_info.get("category", ""),
            "alert_severity": alert_info.get("severity", 0),
            "alert_timestamp": alert.get("@timestamp", ""),
            "source_alert_id": alert.get("_id", ""),
            "source_alert_index": alert.get("_index", ""),
            "related_log_count": 0,
            "error": error,
            "raw_response": raw_response[:500] if raw_response else "",
        }
        if http:
            result["http_method"] = http.get("http_method", "")
            result["http_url"] = http.get("url", "")
            result["http_host"] = http.get("hostname", "")
            result["http_user_agent"] = http.get("http_user_agent", "")
        if payload:
            result["payload"] = payload[:4000]
        return result
