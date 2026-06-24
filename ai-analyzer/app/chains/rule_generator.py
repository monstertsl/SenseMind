"""Stage 6: Suricata 规则生成 Chain

当 AI 确认攻击行为但原始告警未触发 soc.matched 时，
由 AI 生成一条 Suricata 本地规则，写入 local.rules。

仅生成低误报率规则。
"""

import logging
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage
from langchain_core.messages import SystemMessage
from ..json_utils import extract_json

logger = logging.getLogger(__name__)


RULE_GEN_SYSTEM_PROMPT = """你是一个 Suricata IDS 规则专家。你的任务是根据确认的攻击行为，生成一条 Suricata 本地检测规则。

## 规则生成要求

1. 基于 HTTP 协议的攻击，使用 `alert http` 类型
2. 规则需精确匹配攻击 payload 中的特征字符串，避免过于宽泛
3. SID 必须使用 9000001-9999999 范围（AI 本地规则专用段）
4. msg 字段以 "SenseMind AI:" 开头，简述攻击类型
5. 必须包含 `flow:established,to_server` 确保只匹配请求方向
6. 使用 `nocase` 忽略大小写
7. content 匹配应选择攻击 payload 中最独特的部分（避免匹配正常流量）
8. 单个 content 值长度不得少于 10 字节，禁止使用 `<?php`、`GET`、`POST` 等通用字符串作为唯一 content
9. 至少使用 2 个 content 组合匹配，或使用 1 个 content + pcre 组合，确保规则精确

## 误报率评估

你必须评估生成规则的误报风险：

- **low**: 规则匹配的 content 是明确的攻击特征（如 `/etc/passwd`、`UNION SELECT`、`freemarker.template.utility.Execute`），正常流量几乎不会包含。单个 content 不少于 10 字节，且有多个 content 组合
- **medium**: 规则匹配的 content 有一定可能性出现在正常流量中（如普通关键词、常见路径），或只有单个短 content
- **high**: 规则过于宽泛（如只匹配 `<?php`、`GET`、`/`），或单个 content 少于 10 字节，极易误报

**只有 fp_risk 为 "low" 时，should_write 才为 true。**
**注意：`<?php`、`<script`、`GET`、`POST`、`eval` 等通用字符串单独使用时必须判为 high。**

## Suricata 规则语法示例

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SenseMind AI: Directory Traversal etc passwd"; flow:established,to_server; content:"/etc/passwd"; nocase; sid:9000001; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SenseMind AI: SQL Injection UNION SELECT"; flow:established,to_server; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; within:50; sid:9000002; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SenseMind AI: VMware SSTI RCE"; flow:established,to_server; content:"freemarker.template.utility.Execute"; nocase; sid:9000003; rev:1;)
```

注意：content 中的特殊字符（如 `|`、`"`）需要用管道符十六进制编码，例如 `|3c 3f 70 68 70|` 表示 `<?php`。

严格按以下 JSON 格式输出，不要输出其他任何内容：
```json
{
  "rule": "alert http ...",
  "fp_risk": "low",
  "should_write": true,
  "reason": "规则设计说明和误报评估理由"
}
```"""

RULE_GEN_USER_TEMPLATE = """请根据以下确认的攻击行为，生成一条 Suricata 检测规则：

## 告警信息
{alert_summary}

## 攻击判定
- 威胁判定: {threat_verdict}
- 攻击手法: {attack_technique}
- 置信度: {confidence}

## 当前命中的规则
{current_signature}

## 攻击 Payload
{payload}

## 关联日志
{related_logs}

注意：当前告警已被上述规则命中，但该规则可能不是专门针对此攻击模式的。
请评估是否需要生成更精确的检测规则。如果当前规则已充分覆盖此攻击，设置 should_write=false。
请生成 Suricata 规则并评估误报风险，严格按 JSON 格式输出。"""


class GeneratedRule(BaseModel):
    """AI 生成的 Suricata 规则"""

    rule: str = Field(
        description="完整的 Suricata 规则字符串（单行）"
    )
    fp_risk: str = Field(
        description="误报风险等级: low / medium / high"
    )
    should_write: bool = Field(
        description="是否应写入 local.rules，仅当 fp_risk=low 时为 true"
    )
    reason: str = Field(
        description="规则设计说明和误报评估理由"
    )


def create_rule_generator_chain(llm: ChatOpenAI):
    """创建规则生成 Chain

    glm-5.2 不支持 with_structured_output(function calling)，
    改用普通 invoke + 手动 JSON 解析。

    System prompt 不通过 ChatPromptTemplate（避免 JSON 示例中的 {} 被当作模板变量）
    """
    user_prompt = ChatPromptTemplate.from_messages([
        ("human", RULE_GEN_USER_TEMPLATE),
    ])

    def parse_response(input_dict: dict) -> GeneratedRule:
        # 只取模板需要的字段，忽略多余的 key
        template_keys = {"alert_summary", "threat_verdict", "attack_technique",
                         "confidence", "payload", "related_logs", "current_signature"}
        template_input = {k: v for k, v in input_dict.items() if k in template_keys}

        # 反向触发时，在 payload 中标注漏报信息
        if input_dict.get("unalerted_attack_types"):
            unalerted_note = f"\n\n[注意] 此为漏报攻击，未被 Suricata 规则检测到。攻击类型: {input_dict['unalerted_attack_types']}"
            if input_dict.get("unalerted_url"):
                unalerted_note += f"\n漏报 URL: {input_dict['unalerted_url']}"
            template_input["current_signature"] = "（漏报 - 未触发任何 Suricata 规则）" + unalerted_note

        messages = [
            SystemMessage(content=RULE_GEN_SYSTEM_PROMPT),
            *user_prompt.format_messages(**template_input),
        ]
        response = llm.invoke(messages)
        content = response.content.strip()

        data = extract_json(content)
        if data is None:
            logger.warning("RuleGen 返回无法解析: %s", content[:200])
            raise ValueError(f"JSON解析失败: {content[:200]}")

        return GeneratedRule(**data)

    return parse_response
