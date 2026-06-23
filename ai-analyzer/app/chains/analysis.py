"""Stage 5: 最终分析 Chain

综合告警上下文、关联日志、安全知识库，生成结构化研判结果。
"""

import logging
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage
from ..models import AnalysisResult
from ..json_utils import extract_json

logger = logging.getLogger(__name__)


ANALYSIS_SYSTEM_PROMPT = """你是一个专业的 SOC（安全运营中心）安全分析专家。基于告警信息、关联日志和安全知识库，输出威胁研判结果。

你需要基于以下信息进行分析：
1. 告警的 SOC 分类、MITRE ATT&CK 技术编号、攻击阶段
2. 关联的同会话日志（通过 community_id 或 IP+时间窗口关联）
3. 告警签名、五元组、HTTP/TLS/DNS 等协议元数据
4. 安全知识库中的参考信息（MITRE 技术说明、处置手册等）

输出要求：
- threat_verdict: "误报" | "可疑" | "确认威胁" 三选一
- confidence: 0 到 1 之间的小数
- attack_result: "成功" | "失败" | "未知" 三选一
- 如果告警明显是误报（如正常业务流量被误报），直接判为"误报"
- 如果告警真实但无法确认攻击是否成功，判为"可疑"
- 如果告警真实且攻击行为明确，判为"确认威胁"

严格按以下 JSON 格式输出，不要输出其他任何内容：
```json
{
  "threat_verdict": "确认威胁",
  "confidence": 0.9,
  "attack_result": "未知",
  "attack_technique": "攻击手法描述",
  "attack_stage": "攻击阶段",
  "impact_scope": "影响范围评估",
  "attack_chain": "攻击链描述",
  "handling_suggestion": "处置建议",
  "reasoning": "分析推理过程"
}
```"""

ANALYSIS_USER_TEMPLATE = """请分析以下安全告警：

## 主告警信息
{alert_summary}

## SOC 分类
- 分类：{soc_category} ({soc_name})
- MITRE ATT&CK：{mitre_id}
- 攻击阶段：{attack_stage}
- 研判风险等级：{risk}

## 关联日志（{related_count} 条）
{related_logs}

## 安全知识库参考
{knowledge}

请综合以上信息进行威胁研判，严格按 JSON 格式输出分析结果。"""


def create_analysis_chain(llm: ChatOpenAI):
    """创建最终分析 Chain

    glm-5.2 不支持 with_structured_output(function calling)，
    改用普通 invoke + 手动 JSON 解析。

    System prompt 不通过 ChatPromptTemplate（避免 JSON 示例中的 {} 被当作模板变量）
    """
    # 只对 user template 使用 ChatPromptTemplate（system 固定不变）
    user_prompt = ChatPromptTemplate.from_messages([
        ("human", ANALYSIS_USER_TEMPLATE),
    ])

    def parse_response(input_dict: dict) -> AnalysisResult:
        messages = [
            SystemMessage(content=ANALYSIS_SYSTEM_PROMPT),
            *user_prompt.format_messages(**input_dict),
        ]
        response = llm.invoke(messages)
        content = response.content.strip()

        data = extract_json(content)
        if data is None:
            logger.warning("Analysis 返回无法解析: %s", content[:200])
            raise ValueError(f"JSON解析失败: {content[:200]}")

        return AnalysisResult(**data)

    return parse_response
