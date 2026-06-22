"""Stage 1: 告警标准化 Chain

将 Suricata/Zeek 原始 JSON 转换为统一 AlertContext。
纯字段提取，不需要 LLM 调用，用 RunnableLambda 包装为 LCEL 接口。
"""

from langchain_core.runnables import RunnableLambda
from ..models import AlertContext


def normalize_alert(alert: dict) -> AlertContext:
    """从原始告警 JSON 提取标准字段，生成 AlertContext"""
    ctx = AlertContext.from_alert(alert)
    return ctx


# 包装为 Runnable，可接入 LCEL 链
normalize_chain = RunnableLambda(normalize_alert)
