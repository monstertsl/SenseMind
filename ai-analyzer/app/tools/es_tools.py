"""Stage 3: ES 查询工具 - LangChain Tool 封装

将 ESClient 的查询方法封装为 LangChain Tool，
供 Triage Chain 判断后按需调用。
"""

import logging
from langchain_core.tools import tool

logger = logging.getLogger(__name__)


def create_es_tools(es_client):
    """创建 ES 查询工具集，绑定到指定 es_client 实例

    Args:
        es_client: ESClient 实例

    Returns:
        List[BaseTool]: LangChain 工具列表
    """

    @tool
    def query_session_logs(community_id: str, timestamp: str = "") -> str:
        """查询相同 community_id 的关联会话日志。

        Args:
            community_id: 网络会话社区ID
            timestamp: 告警时间戳(ISO8601)，用于时间窗口回退关联

        Returns:
            关联日志的格式化文本
        """
        logs = es_client.query_related_logs(
            community_id=community_id,
            timestamp=timestamp,
        )
        if not logs:
            return "无关联日志"
        logger.info("Tool query_session_logs: community_id=%s, 返回 %d 条", community_id, len(logs))
        return format_logs(logs)

    @tool
    def query_src_ip_history(src_ip: str) -> str:
        """查询源IP的历史告警记录，用于判断是否为重复攻击者。

        Args:
            src_ip: 源IP地址

        Returns:
            历史告警摘要文本
        """
        logs = es_client.query_src_ip_history(src_ip)
        if not logs:
            return "无历史告警记录"
        logger.info("Tool query_src_ip_history: src_ip=%s, 返回 %d 条", src_ip, len(logs))
        return format_logs(logs)

    return [query_session_logs, query_src_ip_history]


def format_logs(logs: list) -> str:
    """格式化日志列表为文本（供 Chain 和 Tool 共用）"""
    if not logs:
        return "无关联日志"

    lines = []
    for i, log in enumerate(logs[:20], 1):
        ts = log.get("@timestamp", "")[:19]
        module = log.get("event", {}).get("module", "")
        kind = log.get("event", {}).get("kind", "")
        event_type = log.get("suricata", {}).get("eve", {}).get("event_type", "")

        sig = ""
        if "suricata" in log:
            sig = log.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", "")

        src = log.get("source", {})
        dst = log.get("destination", {})
        src_str = f"{src.get('ip', '')}:{src.get('port', '')}"
        dst_str = f"{dst.get('ip', '')}:{dst.get('port', '')}"

        line = f"  [{i}] {ts} | {module}/{kind}/{event_type}"
        if sig:
            line += f" | {sig[:60]}"
        line += f" | {src_str} -> {dst_str}"
        lines.append(line)

    return "\n".join(lines)
