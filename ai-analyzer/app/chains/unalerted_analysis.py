"""漏报攻击轻量分析 Chain

为语义检测发现的未触发告警的攻击事件，批量补全 LLM 研判字段。
单次调用处理同一 community_id 下的所有漏报事件，节省 token。

与主分析 Chain 的区别：
- 输入：主告警结论 + 漏报攻击事件列表（批量）
- 输出：JSON 数组，每个元素对应一个漏报事件的研判字段
- threat_verdict 固定为"确认威胁"（语义检测已确认）
- 仅输出 confidence/attack_result/attack_chain/handling_suggestion/impact_scope/reasoning
"""

import logging
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage
from ..json_utils import extract_json_list

logger = logging.getLogger(__name__)


UNALERTED_SYSTEM_PROMPT = """你是一个专业的 SOC（安全运营中心）安全分析专家。

语义检测引擎已从关联日志中确认了攻击行为（未触发 Suricata 告警的漏报攻击）。
这些攻击通过递归解码 + 语法分析确认，threat_verdict 固定为"确认威胁"。

你的任务是为每个漏报攻击补全研判信息，结合主告警的上下文进行综合评估。

## 动态基线预判机制

由于 Suricata 的 http-body-printable 只在 alert 事件中记录响应体，纯 http 事件（漏报攻击）通常没有响应体可用。
为此系统会从同会话构建动态响应长度基线（±20% 容差），并在输入中提供"动态基线预判"信息：
- 响应长度：漏报攻击的 HTTP 响应字节数
- 基线样本：构建基线使用的样本数量（同会话非攻击 200 响应 + 非 200 alert + 已确认失败的 200 alert）
- 预判结果："失败"（落在基线正常范围内，前端已拦截）或"未知"（偏离基线，可能成功）

## attack_result 判断规则

按以下优先级判断：
1. 响应状态码为 403/404/405/500 → "失败"（服务端拒绝）
2. 响应状态码为 200：
   - 有响应体且包含攻击成功特征（如命令回显、敏感文件内容、webshell 回连） → "成功"
   - 有"动态基线预判"且预判结果为"失败" → "失败"（前端拦截，响应长度与正常请求一致）
   - 有"动态基线预判"且预判结果为"未知" → "未知"（响应偏离基线，但无响应体确证）
   - 无基线预判且无响应体 → "未知"
3. 其他状态码或无响应数据 → "未知"

注意：
- 响应体由 Suricata http-body-printable 提取，非 ASCII 字符（如中文）会被替换为"."，连续的"...."应理解为正常页面文本
- 基线预判仅作为辅助证据，若响应体明显包含攻击成功特征应优先判"成功"
- 基线样本数较少（<3）时预判可信度低，应更保守地判"未知"

输出字段说明：
- confidence: 置信度 0-1（语义检测已确认，通常 0.7 以上）
- attack_result: "成功" | "失败" | "未知"（按上述规则判断）
- attack_chain: 攻击链描述（结合主告警上下文分析攻击者意图）
- handling_suggestion: 处置建议
- impact_scope: 影响范围评估
- reasoning: 简要分析推理（如有基线预判，需说明如何参考）

严格按以下 JSON 数组格式输出，每个元素对应一个漏报攻击，顺序与输入一致，不要输出其他内容：
```json
[
  {
    "confidence": 0.85,
    "attack_result": "未知",
    "attack_chain": "攻击链描述",
    "handling_suggestion": "处置建议",
    "impact_scope": "影响范围",
    "reasoning": "分析推理"
  }
]
```"""

UNALERTED_USER_TEMPLATE = """## 主告警研判结论
{main_alert_summary}

## 漏报攻击事件（{count} 个）
{unalerted_list}

请为每个漏报攻击补全研判信息，严格按 JSON 数组格式输出，元素顺序与漏报攻击列表一致。"""


def create_unalerted_analysis_chain(llm: ChatOpenAI):
    """创建漏报攻击轻量分析 Chain

    单次 LLM 调用批量处理所有漏报事件，输出 JSON 数组。
    复用主分析器的 LLM 实例，不新增模型配置。
    """
    user_prompt = ChatPromptTemplate.from_messages([
        ("human", UNALERTED_USER_TEMPLATE),
    ])

    def parse_response(input_dict: dict) -> list[dict]:
        messages = [
            SystemMessage(content=UNALERTED_SYSTEM_PROMPT),
            *user_prompt.format_messages(**input_dict),
        ]
        response = llm.invoke(messages)
        content = response.content.strip()

        data = extract_json_list(content)
        if data is None:
            logger.warning("漏报轻量分析返回无法解析: %s", content[:200])
            return []

        # 补全模型可能缺失的字段
        results = []
        for item in data:
            if not isinstance(item, dict):
                continue
            for field in ["attack_chain", "handling_suggestion", "impact_scope", "reasoning"]:
                if field not in item:
                    item[field] = "N/A"
            if "confidence" not in item or not isinstance(item.get("confidence"), (int, float)):
                item["confidence"] = 0.7
            if "attack_result" not in item:
                item["attack_result"] = "未知"
            results.append(item)
        return results

    return parse_response
