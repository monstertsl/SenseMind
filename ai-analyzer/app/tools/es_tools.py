"""Stage 3: ES 查询工具 - LangChain Tool 封装

将 ESClient 的查询方法封装为 LangChain Tool，
供 Triage Chain 判断后按需调用。
"""

import logging
from langchain_core.tools import tool
from ..http_utils import decode_http_body

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
    """格式化日志列表为文本（供 Chain 和 Tool 共用）

    支持 Suricata 和 Zeek 两种数据源。
    """
    if not logs:
        return "无关联日志"

    lines = []
    for i, log in enumerate(logs[:20], 1):
        ts = log.get("@timestamp", "")[:19]
        module = log.get("event", {}).get("module", "")
        kind = log.get("event", {}).get("kind", "")
        dataset = log.get("event", {}).get("dataset", "")
        event_type = log.get("suricata", {}).get("eve", {}).get("event_type", "")

        sig = ""
        if "suricata" in log:
            sig = log.get("suricata", {}).get("eve", {}).get("alert", {}).get("signature", "")

        src = log.get("source", {})
        dst = log.get("destination", {})
        src_str = f"{src.get('ip', '')}:{src.get('port', '')}"
        dst_str = f"{dst.get('ip', '')}:{dst.get('port', '')}"

        # 提取协议/应用层信息（Suricata 或 Zeek）
        detail = ""
        if event_type == "http" or dataset == "zeek.http":
            # Suricata HTTP
            sc_http = log.get("suricata", {}).get("eve", {}).get("http", {})
            method = sc_http.get("http_method", "")
            url = sc_http.get("url", "")
            host = sc_http.get("hostname", "")
            ua = sc_http.get("http_user_agent", "")
            status = sc_http.get("status", "")
            resp_len = sc_http.get("length", "")
            resp_body = decode_http_body(sc_http, "http_response_body")
            # Zeek HTTP 回退
            if not method:
                method = log.get("http", {}).get("request", {}).get("method", "")
            if not url:
                url = log.get("url", {}).get("original", "")
            if not host:
                host = log.get("url", {}).get("domain", "")
            if not status:
                status = log.get("http", {}).get("response", {}).get("status_code", "")
            detail = f" | {method} {host}{url}"
            if status:
                detail += f" -> {status}"
            if resp_len:
                detail += f" ({resp_len}B)"
            if ua:
                detail += f" UA={ua[:50]}"
            if resp_body:
                detail += f" RESP={resp_body[:200]}"
        elif event_type == "dns" or dataset == "zeek.dns":
            # Suricata DNS
            sc_dns = log.get("suricata", {}).get("eve", {}).get("dns", {})
            query = sc_dns.get("query", "") if isinstance(sc_dns, dict) else ""
            rcode = sc_dns.get("rcode", "") if isinstance(sc_dns, dict) else ""
            # Zeek DNS 回退
            if not query:
                query = log.get("dns", {}).get("question", {}).get("name", "")
            if not rcode:
                rcode = log.get("dns", {}).get("response_code", "")
            detail = f" | DNS {query} rcode={rcode}"
        elif event_type == "tls" or dataset == "zeek.ssl":
            sni = log.get("suricata", {}).get("eve", {}).get("tls", {}).get("sni", "")
            if not sni:
                # Zeek SSL 日志的 SNI 可能在 zeek.ssl.server_name
                sni = log.get("zeek", {}).get("ssl", {}).get("server_name", "")
            detail = f" | TLS SNI={sni}" if sni else ""
        elif event_type == "fileinfo":
            filename = log.get("suricata", {}).get("eve", {}).get("fileinfo", {}).get("filename", "")
            detail = f" | FILE {filename}" if filename else ""

        # 标签：模块/类型
        type_label = f"{module}/{event_type}" if event_type else f"{module}/{dataset}"

        line = f"  [{i}] {ts} | {type_label}"
        if sig:
            line += f" | {sig[:60]}"
        line += f" | {src_str} -> {dst_str}"
        line += detail
        lines.append(line)

    return "\n".join(lines)
