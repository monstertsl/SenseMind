"""AI 分析提示词模板"""

# SOC 安全分析系统提示词
SYSTEM_PROMPT = """你是一个专业的 SOC（安全运营中心）安全分析专家。你的任务是分析 Suricata/Zeek 告警日志，输出威胁研判结果。

你需要基于以下信息进行分析：
1. 告警的 SOC 分类、MITRE ATT&CK 技术编号、攻击阶段
2. 关联的同会话日志（通过 community_id 或 IP+时间窗口关联）
3. 告警签名、五元组、HTTP/TLS/DNS 等协议元数据

输出要求（严格按以下 JSON 格式，不要输出其他内容）：
```json
{
  "threat_verdict": "误报 | 可疑 | 确认威胁",
  "confidence": 0.0到1.0的置信度,
  "attack_result": "攻击结果判定：成功 | 失败 | 未知",
  "attack_technique": "攻击手法描述",
  "attack_stage": "攻击阶段（初始访问/执行/持久化/权限提升/防御绕过/凭据窃取/发现/横向移动/收集/命令与控制/数据外泄/影响）",
  "impact_scope": "影响范围评估，包括受影响资产、潜在损失",
  "attack_chain": "如果检测到攻击链，描述攻击者从初始访问到当前阶段的行为路径；如果单条告警无法判断攻击链，填'暂无法判断'",
  "handling_suggestion": "处置建议，包括阻断措施、加固建议、后续监控方向",
  "reasoning": "分析推理过程，简述为何得出上述结论"
}
```

注意事项：
- threat_verdict 只能是 "误报"、"可疑"、"确认威胁" 三选一
- attack_result 只能是 "成功"、"失败"、"未知" 三选一
- confidence 是 0 到 1 之间的小数
- 如果告警明显是误报（如正常业务流量被误报），直接判为"误报"
- 如果告警真实但无法确认攻击是否成功，判为"可疑"
- 如果告警真实且攻击行为明确，判为"确认威胁"
"""

# 告警分析用户提示词模板
ANALYSIS_PROMPT_TEMPLATE = """请分析以下安全告警：

## 主告警信息
{alert_summary}

## SOC 分类
- 分类：{soc_category} ({soc_name})
- MITRE ATT&CK：{mitre_id}
- 攻击阶段：{attack_stage}

## 关联日志（{related_count} 条）
{related_logs}

请根据以上信息进行威胁研判，按指定 JSON 格式输出分析结果。"""


def format_alert_summary(alert: dict) -> str:
    """格式化主告警摘要"""
    lines = []
    eve = alert.get("suricata", {}).get("eve", {})
    alert_info = eve.get("alert", {})

    lines.append(f"- 时间: {alert.get('@timestamp', 'N/A')}")
    lines.append(f"- 签名: {alert_info.get('signature', 'N/A')}")
    lines.append(f"- 分类: {alert_info.get('category', 'N/A')}")
    lines.append(f"- 严重等级: {alert_info.get('severity', 'N/A')}")

    src = alert.get("source", {})
    dst = alert.get("destination", {})
    lines.append(
        f"- 源: {src.get('ip', 'N/A')}:{src.get('port', 'N/A')} -> "
        f"目的: {dst.get('ip', 'N/A')}:{dst.get('port', 'N/A')}"
    )
    lines.append(f"- 协议: {alert.get('network', {}).get('transport', 'N/A')}")

    http = eve.get("http", {})
    if http:
        lines.append(f"- HTTP方法: {http.get('http_method', 'N/A')}")
        lines.append(f"- HTTP URL: {http.get('url', 'N/A')}")
        lines.append(f"- HTTP Host: {http.get('hostname', 'N/A')}")
        lines.append(f"- User-Agent: {http.get('http_user_agent', 'N/A')}")

    tls = eve.get("tls", {})
    if tls:
        lines.append(f"- TLS SNI: {tls.get('sni', 'N/A')}")

    # payload 可读内容（截断到 2000 字符）
    payload = eve.get("payload_printable", "")
    if payload:
        lines.append(f"- Payload:\n{payload[:2000]}")

    return "\n".join(lines)


def format_related_logs(logs: list) -> str:
    """格式化关联日志"""
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
