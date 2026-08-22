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


# ============================================================
# Stage 5a: 溯源分析（独立阶段）
# 目的：深入还原流量真实性质，避免只看源/目的 IP 就下结论。
# ============================================================
TRACE_SYSTEM_PROMPT = """你是一个专业的 SOC 流量溯源分析专家。你的任务是客观还原告警流量的**真实性质**，而不是急着下威胁判定。

请基于以下信息，客观、完整地还原这条流量到底发生了什么：

1. **流量四元组**（源IP:源端口 → 目的IP:目的端口）：
   - 结合知识库中的端口语义，推断目标可能运行的服务类型。
   - 注意端口仅是参考，真实服务需结合协议解析结果和 payload 内容综合判断，避免机械套用端口默认映射。

2. **协议信息**：
   - 结合传输层协议（TCP/UDP）与应用层协议（HTTP/DNS/TLS/SMB 等，如有），判断这条流量的通信性质。

3. **payload 的实际内容**：
   - 客观描述 payload 里实际有什么：请求/响应内容、数据格式、出现的字符串、IP、时间、URL、命令等。
   - 不要只盯着攻击特征字符串，要看 payload 整体在表达什么。
   - 如果 payload 内容看起来像某种数据或文本的传输（而非直接的请求/响应交互），请如实描述其形态。

4. **时间信息**：
   - 关注告警时间与 payload 中出现的任何时间信息的相对关系，若有明显差异请指出。
   - 输入中的时间戳均为 UTC（0 时区，如 "2026-08-21T16:21:42Z"）。你在输出中引用任何时间时，必须**原样保留数值**（不要自行做时区换算），并在时间后标注时区，例如 "2026-08-21 16:21:42 (UTC)"。这样读者可自行换算为本地时间。

请还原并回答：这条流量从发起方到接收方，实际上在传递什么、在做什么？

严格按以下 JSON 格式输出，不要输出其他任何内容：
```json
{
  "traffic_nature": "这条流量真实在做什么（客观描述）",
  "target_service": "目标服务类型判断（结合端口与协议/payload 综合推断，无法确定则说明）",
  "protocol_observation": "协议层面的观察（传输层/应用层，是否识别为具体协议）",
  "payload_content": "payload 实际内容的客观描述（含形态、关键字符串、IP、时间、URL、命令等）",
  "time_observation": "payload 中的时间信息与告警时间的关系（无则说明无时间信息）",
  "trace_conclusion": "溯源结论：这段流量真实在做什么"
}
```"""

TRACE_USER_TEMPLATE = """请对以下告警流量做溯源分析：

## 主告警信息
{alert_summary}

## SOC 分类
- 分类：{soc_category} ({soc_name})
- MITRE ATT&CK：{mitre_id}

## 关联日志（{related_count} 条）
{related_logs}

## 安全知识库参考
{knowledge}

请严格按 JSON 格式输出溯源分析结果。"""


# ============================================================
# Stage 5b: 综合研判（基于溯源结论）
# ============================================================
ANALYSIS_SYSTEM_PROMPT = """你是一个专业的 SOC（安全运营中心）安全分析专家。基于告警信息、关联日志、溯源分析结论和安全知识库，输出最终威胁研判结果。

你必须**严格基于溯源分析结论**进行研判：
- 溯源结论还原了流量的真实性质，你的研判必须与之自洽。如果溯源结论表明流量并非真实的攻击行为，应判为"误报"，不得仅因 payload 中出现攻击特征字符串就判为威胁。
- 处置建议（handling_suggestion）必须**与溯源结论和研判结果保持一致**：
  - 若判定为误报 → 建议优化规则/白名单/忽略，而非按攻击处置（如封禁、隔离）
  - 若判定为真实威胁 → 给出相应的封禁、隔离、补丁、排查等处置
  - 处置建议要落到「这条流量到底是什么」上，避免泛泛而谈

输出要求：
- threat_verdict: "误报" | "可疑" | "确认威胁" 三选一
- confidence: 0 到 1 之间的小数
- attack_result: "成功" | "失败" | "未知" 三选一
- 输入中的时间戳均为 UTC（0 时区）。在 attack_chain、handling_suggestion、reasoning 等文本字段中引用任何时间时，必须**原样保留数值**（不要自行换算时区），并在时间后标注时区，例如 "2026-08-21 16:21:42 (UTC)"。
- 如果告警明显是误报（如正常业务流量、文件传输、日志转发被误报），直接判为"误报"
- 如果告警真实但无法确认攻击是否成功，判为"可疑"
- 如果告警真实且攻击行为明确，判为"确认威胁"

attack_result（攻击结果）判定规则 —— 必须基于响应证据，严禁仅凭请求 payload 推断：
- "成功"：响应状态码为 200 且响应体中包含攻击成功的特征（如 SQL 报错信息、命令执行输出、敏感文件内容回显、webshell 连接成功），或响应体明确反映出攻击已生效
- "失败"：响应状态码为 403/404/500/WAF 拦截页面，或响应体明确表示攻击被拒绝/未生效
- "未知"：关联日志中没有响应数据（无状态码、无响应体），或响应证据不足以判断攻击是否生效时，必须判为"未知"
- 关键原则：仅看到攻击请求（payload 中包含攻击特征）而看不到任何响应，不能判为"成功"，必须判为"未知"

注意：响应体由 Suricata http-body-printable 提取，仅保留可打印 ASCII 字符，非 ASCII 字符（如中文）会被替换为"."。因此响应体中连续的"...."通常是被替换的中文内容，应理解为正常页面文本，不要误判为攻击成功的特征。

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

## 溯源分析结论（必须严格参考）
{trace_conclusion}

## 关联日志（{related_count} 条）
{related_logs}

## 安全知识库参考
{knowledge}

请综合以上信息（尤其溯源分析结论）进行威胁研判，严格按 JSON 格式输出分析结果。"""


def create_analysis_chain(llm: ChatOpenAI):
    """创建最终分析 Chain（两阶段：先溯源分析，再综合研判）

    glm-5.2 不支持 with_structured_output(function calling)，
    改用普通 invoke + 手动 JSON 解析。

    System prompt 不通过 ChatPromptTemplate（避免 JSON 示例中的 {} 被当作模板变量）
    """
    trace_user_prompt = ChatPromptTemplate.from_messages([
        ("human", TRACE_USER_TEMPLATE),
    ])
    analysis_user_prompt = ChatPromptTemplate.from_messages([
        ("human", ANALYSIS_USER_TEMPLATE),
    ])

    def _invoke_json(system_prompt: str, user_messages) -> dict:
        messages = [SystemMessage(content=system_prompt), *user_messages]
        response = llm.invoke(messages)
        content = response.content.strip()
        data = extract_json(content)
        if data is None:
            logger.warning("LLM 返回无法解析: %s", content[:200])
            raise ValueError(f"JSON解析失败: {content[:200]}")
        return data

    def parse_response(input_dict: dict) -> AnalysisResult:
        # ---- Stage 5a: 溯源分析 ----
        trace_input = {
            "alert_summary": input_dict["alert_summary"],
            "soc_category": input_dict["soc_category"],
            "soc_name": input_dict["soc_name"],
            "mitre_id": input_dict["mitre_id"],
            "related_count": input_dict["related_count"],
            "related_logs": input_dict["related_logs"],
            "knowledge": input_dict["knowledge"],
        }
        try:
            trace_data = _invoke_json(
                TRACE_SYSTEM_PROMPT,
                trace_user_prompt.format_messages(**trace_input),
            )
            # 溯源结论格式化为文本，供研判阶段引用
            trace_conclusion = "\n".join(
                f"- {k}: {v}" for k, v in trace_data.items()
            )
            logger.info("溯源分析完成: traffic_nature=%s",
                        trace_data.get("traffic_nature"))
        except Exception as e:
            logger.warning("溯源分析失败，降级为无溯源结论: %s", e)
            trace_conclusion = "溯源分析失败，无法提供溯源结论"

        # ---- Stage 5b: 综合研判（引用溯源结论）----
        analysis_input = dict(input_dict)
        analysis_input["trace_conclusion"] = trace_conclusion
        data = _invoke_json(
            ANALYSIS_SYSTEM_PROMPT,
            analysis_user_prompt.format_messages(**analysis_input),
        )

        # 补全模型可能缺失的字段
        for field in ["threat_verdict", "attack_result", "attack_technique",
                      "attack_stage", "impact_scope", "attack_chain",
                      "handling_suggestion", "reasoning"]:
            if field not in data:
                data[field] = "N/A" if field != "confidence" else 0.3
        if "confidence" not in data or not isinstance(data.get("confidence"), (int, float)):
            data["confidence"] = 0.3

        return AnalysisResult(**data)

    return parse_response
