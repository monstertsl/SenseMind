"""Stage 2: 告警研判 Chain

AI 快速评估单条告警，判断是否需要进一步调查。
输出结构化 TriageResult，驱动后续动态查询决策。
"""

import logging
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage
from ..models import TriageResult
from ..json_utils import extract_json

logger = logging.getLogger(__name__)


TRIAGE_SYSTEM_PROMPT = """你是一个 SOC 安全研判专家。你的任务是快速评估一条安全告警，判断是否需要进一步调查。

根据告警信息，判断：

1. need_session_query: 是否需要查询同 community_id 的关联日志（会话日志）
   - 高严重等级(severity>=2)或涉及攻击类告警 → true
   - 低严重等级的信息类告警 → false

2. need_history_query: 是否需要查询源IP历史行为
   - 可疑IP、重复攻击、内网横向 → true
   - 单次低风险告警 → false

3. risk: 当前风险等级
   - critical: 确认的入侵行为（RCE成功、C2通信、数据外泄）
   - high: 可能为真实攻击（SQL注入、目录遍历、漏洞利用尝试）
   - medium: 可疑行为（扫描、暴力破解尝试）
   - low: 低风险（信息类、误报可能性大）

严格按以下 JSON 格式输出，不要输出其他任何内容：
```json
{
  "need_session_query": true,
  "need_history_query": false,
  "risk": "high",
  "triage_reason": "研判理由"
}
```"""

TRIAGE_USER_TEMPLATE = """请研判以下告警：

{alert_summary}

SOC分类: {soc_category} ({soc_name})
MITRE ATT&CK: {mitre_id}
攻击阶段: {attack_stage}

请输出结构化研判结果。"""


def create_triage_chain(llm: ChatOpenAI):
    """创建告警研判 Chain

    glm-5.2 不支持 with_structured_output(function calling)，
    改用普通 invoke + 手动 JSON 解析。

    System prompt 不通过 ChatPromptTemplate（避免 JSON 示例中的 {} 被当作模板变量）
    """
    user_prompt = ChatPromptTemplate.from_messages([
        ("human", TRIAGE_USER_TEMPLATE),
    ])

    def parse_response(input_dict: dict) -> TriageResult:
        messages = [
            SystemMessage(content=TRIAGE_SYSTEM_PROMPT),
            *user_prompt.format_messages(**input_dict),
        ]
        response = llm.invoke(messages)
        content = response.content.strip()

        data = extract_json(content)
        if data is None:
            logger.warning("Triage 返回无法解析: %s", content[:200])
            return TriageResult(
                need_session_query=True,
                need_history_query=False,
                risk="medium",
                triage_reason="研判解析失败，使用默认策略",
            )

        return TriageResult(**data)

    return parse_response
