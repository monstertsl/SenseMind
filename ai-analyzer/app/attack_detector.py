"""未触发告警的攻击事件检测

从同 community_id 的关联日志中，提取未触发 Suricata alert 的 HTTP 事件，
检测其中是否包含攻击特征（但未被规则覆盖）。

供 Stage 6 反向触发使用：AI 分析一条告警时，顺带检查同会话的非 alert 事件，
为漏报的攻击生成检测规则。
"""

import logging
from urllib.parse import unquote

logger = logging.getLogger(__name__)


# 攻击特征关键词（按攻击类型分组）
ATTACK_PATTERNS = {
    "ognl_injection": [
        "getRuntime", "IOUtils", "opensymphony", "ServletActionContext",
        "ognl", "#a=", "@java", "@org.apache",
    ],
    "ssti": [
        "${", "#{", "*{", "{{",
    ],
    "rce_command_injection": [
        "|echo", "|cat", "|id", "|whoami", "|wget", "|curl",
        ";echo", ";cat", ";id", ";whoami",
        "$(echo", "$(", "system(", "exec(", "passthru(",
    ],
    "webshell_upload": [
        "<?php", "<?=", "eval(", "base64_decode", "assert(",
        "shell_exec", "system(", "passthru(", "unlink(__FILE__)",
    ],
    "file_read_traversal": [
        "/etc/passwd", "/etc/shadow", "..%2f", "%2e%2e",
        "file:///", "file:///etc",
    ],
    "sql_injection": [
        "union select", "union all select", "extractvalue(",
        "updatexml(", "benchmark(", "sleep(", "load_file(",
        "information_schema", "0x7e",
    ],
    "ssrf": [
        "file://", "gopher://", "dict://", "ldap://",
        "169.254.169.254", "metadata.google",
    ],
    "xxe": [
        "<!entity", "<!doctype", "system \"file:",
        "ENTITY disclose", "external entity",
    ],
    "deserialization": [
        "rO0AB", "java.lang.Runtime", "invokertransformer",
        "templatesimpl", "beanfactory",
    ],
    "confluence_ognl": [
        "createpage-entervariables", "queryString=",
    ],
    "druid": [
        "druid/indexer", "firehose", "uris",
    ],
    "spring_spel": [
        "AddResponseHeader", "T(java.lang.Runtime)",
        "T(org.springframework", "copyToByteArray",
    ],
}


def detect_attack_in_http_event(log: dict) -> list[str]:
    """检测单条 HTTP 事件中是否包含攻击特征

    Args:
        log: ES 中的日志文档（Suricata http 事件或 Zeek http 日志）

    Returns:
        命中的攻击类型列表
    """
    # 提取 URL 和 payload
    url = ""
    payload = ""

    # Suricata http 事件
    eve = log.get("suricata", {}).get("eve", {})
    if eve.get("event_type") == "http":
        http = eve.get("http", {})
        url = http.get("url", "")
        payload = eve.get("payload_printable", "")

    # Zeek http 日志
    if not url and log.get("event", {}).get("dataset") == "zeek.http":
        url = log.get("url", {}).get("original", "")

    # 也检查 event.original（原始 JSON）
    if not url and not payload:
        original = log.get("event", {}).get("original", "")
        if original:
            payload = original

    if not url and not payload:
        return []

    # URL 解码后检测
    url_decoded = unquote(url) if url else ""
    text_to_check = f"{url_decoded} {payload}".lower()

    matched_types = []
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in text_to_check:
                matched_types.append(attack_type)
                break

    return matched_types


def find_unalerted_attacks(related_logs: list) -> list[dict]:
    """从关联日志中找出未触发 alert 的攻击 HTTP 事件

    Args:
        related_logs: 同 community_id 的关联日志列表

    Returns:
        未触发 alert 但包含攻击特征的 HTTP 事件列表
        [{"log": log, "attack_types": [...], "url": "...", "payload": "..."}]
    """
    # 收集已触发 alert 的时间戳和 tx_id，避免重复
    alerted_tx_ids = set()
    for log in related_logs:
        eve = log.get("suricata", {}).get("eve", {})
        if eve.get("event_type") == "alert":
            tx_id = eve.get("tx_id")
            if tx_id:
                alerted_tx_ids.add(tx_id)

    unalerted = []
    for log in related_logs:
        eve = log.get("suricata", {}).get("eve", {})
        event_type = eve.get("event_type", "")

        # 只检查 http 事件（非 alert）
        if event_type != "http":
            # Zeek http 日志也检查
            if log.get("event", {}).get("dataset") != "zeek.http":
                continue

        # 检查是否已被 alert 覆盖（同 tx_id）
        tx_id = eve.get("tx_id")
        if tx_id and tx_id in alerted_tx_ids:
            continue

        # 检测攻击特征
        attack_types = detect_attack_in_http_event(log)
        if attack_types:
            url = eve.get("http", {}).get("url", "")
            if not url:
                url = log.get("url", {}).get("original", "")
            payload = eve.get("payload_printable", "")[:500]

            unalerted.append({
                "attack_types": attack_types,
                "url": url[:200],
                "payload": payload,
                "timestamp": log.get("@timestamp", ""),
            })
            logger.info(
                "发现未触发告警的攻击事件: types=%s, url=%s",
                attack_types, url[:80],
            )

    return unalerted
