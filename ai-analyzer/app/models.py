"""数据模型 - 各阶段 Chain 的输入输出"""

from pydantic import BaseModel, Field


class AlertContext(BaseModel):
    """标准化后的告警上下文 - Stage 1 输出

    将 Suricata/Zeek 不同来源的原始 JSON 统一为标准格式。
    """

    timestamp: str = ""
    signature: str = ""
    signature_id: int = 0
    category: str = ""
    severity: int = 0
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    community_id: str = ""

    # SOC 分类
    soc_category: str = ""
    soc_name: str = ""
    mitre_id: str = ""
    attack_stage: str = ""

    # HTTP 元数据
    http_method: str = ""
    http_url: str = ""
    http_host: str = ""
    http_user_agent: str = ""

    # TLS
    tls_sni: str = ""

    # Payload
    payload: str = ""

    # 原始告警引用（不序列化）
    raw_alert: dict = Field(default_factory=dict, exclude=True)

    @classmethod
    def from_alert(cls, alert: dict) -> "AlertContext":
        """从原始告警 JSON 提取标准字段"""
        eve = alert.get("suricata", {}).get("eve", {})
        alert_info = eve.get("alert", {})
        src = alert.get("source", {})
        dst = alert.get("destination", {})
        network = alert.get("network", {})
        http = eve.get("http", {})
        tls = eve.get("tls", {})
        soc = alert.get("soc", {})
        payload = eve.get("payload_printable", "")

        return cls(
            timestamp=alert.get("@timestamp", ""),
            signature=alert_info.get("signature", ""),
            signature_id=alert_info.get("signature_id", 0),
            category=alert_info.get("category", ""),
            severity=alert_info.get("severity", 0),
            src_ip=src.get("ip", ""),
            src_port=src.get("port", 0),
            dst_ip=dst.get("ip", ""),
            dst_port=dst.get("port", 0),
            protocol=network.get("transport", ""),
            community_id=network.get("community_id", ""),
            soc_category=soc.get("category", ""),
            soc_name=soc.get("name", ""),
            mitre_id=soc.get("mitre_id", ""),
            attack_stage=soc.get("stage", ""),
            http_method=http.get("http_method", ""),
            http_url=http.get("url", ""),
            http_host=http.get("hostname", ""),
            http_user_agent=http.get("http_user_agent", ""),
            tls_sni=tls.get("sni", ""),
            payload=payload[:2000] if payload else "",
            raw_alert=alert,
        )

    def to_summary(self) -> str:
        """生成告警摘要文本，供后续 Chain 使用"""
        lines = [
            f"- 时间: {self.timestamp}",
            f"- 签名: {self.signature}",
            f"- 分类: {self.category}",
            f"- 严重等级: {self.severity}",
            f"- 源: {self.src_ip}:{self.src_port} -> 目的: {self.dst_ip}:{self.dst_port}",
            f"- 协议: {self.protocol}",
        ]
        if self.http_method:
            lines.append(f"- HTTP: {self.http_method} {self.http_host}{self.http_url}")
        if self.http_user_agent:
            lines.append(f"- User-Agent: {self.http_user_agent}")
        if self.tls_sni:
            lines.append(f"- TLS SNI: {self.tls_sni}")
        if self.payload:
            lines.append(f"- Payload:\n{self.payload[:1000]}")
        return "\n".join(lines)


class TriageResult(BaseModel):
    """告警研判结果 - Stage 2 输出"""

    need_session_query: bool = Field(
        description="是否需要查询 community_id 关联日志"
    )
    need_history_query: bool = Field(
        description="是否需要查询源IP历史行为"
    )
    need_threat_intel: bool = Field(
        description="是否需要查询威胁情报"
    )
    risk: str = Field(
        description="当前风险等级: low / medium / high / critical"
    )
    triage_reason: str = Field(
        description="研判理由，简述为何做出上述判断"
    )


class AnalysisResult(BaseModel):
    """最终分析结果 - Stage 5 输出"""

    threat_verdict: str = Field(
        description="威胁判定: 误报 / 可疑 / 确认威胁"
    )
    confidence: float = Field(
        description="置信度 0.0-1.0"
    )
    attack_result: str = Field(
        description="攻击结果: 成功 / 失败 / 未知"
    )
    attack_technique: str = Field(
        description="攻击手法描述"
    )
    attack_stage: str = Field(
        description="攻击阶段"
    )
    impact_scope: str = Field(
        description="影响范围评估"
    )
    attack_chain: str = Field(
        description="攻击链描述，无法判断时填'暂无法判断'"
    )
    handling_suggestion: str = Field(
        description="处置建议"
    )
    reasoning: str = Field(
        description="分析推理过程"
    )
