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

## HTTP Sticky Buffer 使用（关键！）

在 `alert http` 规则中，**plain `content`（不带 sticky buffer）默认只匹配 HTTP 请求体（body），不会匹配 URL/URI**。
如果攻击特征出现在 URL 中（路径、查询参数等），必须使用 sticky buffer 指定匹配位置，否则规则永远不会命中。

可用 sticky buffer：
- `http.uri` — 规范化（自动解码 %20 等）的 URI。推荐用于 URL 匹配，可覆盖多种编码绕过
- `http.uri.raw` — 原始 URI（保留编码），如需匹配 `%20` 等编码字符本身时使用
- `http.method` — HTTP 方法（GET / POST 等）
- `http.request_body` — 请求体（POST payload）
- `http.request_line` — 完整请求行（如 `GET /path?param HTTP/1.1`）
- `http.header` — HTTP 请求头
- `http.user_agent` — User-Agent

**sticky buffer 规则**：
- 攻击特征在 URL 路径或 GET 参数中 → 使用 `http.uri`
- 攻击特征在 POST body 中 → 使用 `http.request_body`
- 多个 content 匹配同一 buffer（如都在 URI 中），只需在第一个 content 前加 `http.uri;`，后续 content 自动延续在同一 buffer
- 若 content 需要跨 buffer 匹配（如路径在 URI、payload 在 body），分别用不同 sticky buffer
- **注意**：`http.uri` 会自动解码 `%20`→空格、`%2f`→`/` 等，所以 content 应写解码后的值（如 `cat /etc/passwd` 而非 `cat%20/etc/passwd`）

## 源/目的地址选择（关键）

你必须根据告警信息中的源 IP 和目的 IP 判断流量方向，选择正确的地址组。
Suricata 默认配置：HOME_NET = [192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12]，EXTERNAL_NET = !$HOME_NET。

判断规则：
- **源 IP 在 10.x / 172.16-31.x / 192.168.x 且目的 IP 也在内网段** → 内网横向移动，源用 `[$HOME_NET,$EXTERNAL_NET]`（或 `any`），目的用 `$HOME_NET`
- **源 IP 在内网段、目的 IP 在公网** → 出站攻击（如 C2 回连、数据外泄），源用 `$HOME_NET`，目的用 `$EXTERNAL_NET`
- **源 IP 在公网、目的 IP 在内网段** → 外网入站攻击，源用 `$EXTERNAL_NET`，目的用 `$HOME_NET`
- **无法确定方向或需通用覆盖** → 源用 `any`，目的用 `$HOME_NET`

**默认推荐**：对于入站 Web 攻击（命令注入、LFI、RCE、SQLi 等），源地址用 `any`（同时覆盖外网攻击和内网横向移动），目的地址用 `$HOME_NET`。
因为 content 匹配已确保规则精确，无需靠源地址限制来防误报；而限定 `$EXTERNAL_NET` 会漏检内网横向攻击。

## 误报率评估

你必须评估生成规则的误报风险：

- **low**: 规则匹配的 content 是明确的攻击特征（如 `/etc/passwd`、`UNION SELECT`、`freemarker.template.utility.Execute`），正常流量几乎不会包含。单个 content 不少于 10 字节，且有多个 content 组合
- **medium**: 规则匹配的 content 有一定可能性出现在正常流量中（如普通关键词、常见路径），或只有单个短 content
- **high**: 规则过于宽泛（如只匹配 `<?php`、`GET`、`/`），或单个 content 少于 10 字节，极易误报

**只有 fp_risk 为 "low" 时，should_write 才为 true。**
**注意：`<?php`、`<script`、`GET`、`POST`、`eval` 等通用字符串单独使用时必须判为 high。**

## Suricata 规则语法示例

```
alert http any any -> $HOME_NET any (msg:"SenseMind AI: Directory Traversal etc passwd"; flow:established,to_server; http.uri; content:"/etc/passwd"; nocase; sid:9000001; rev:1;)
alert http any any -> $HOME_NET any (msg:"SenseMind AI: SQL Injection UNION SELECT"; flow:established,to_server; http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; within:50; sid:9000002; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SenseMind AI: VMware SSTI RCE"; flow:established,to_server; http.uri; content:"/catalog-portal/ui/oauth/verify"; nocase; content:"freemarker.template.utility.Execute"; nocase; distance:0; within:100; sid:9000003; rev:1;)
alert http any any -> $HOME_NET any (msg:"SenseMind AI: PHP Webshell via unlink"; flow:established,to_server; http.request_body; content:"|3c 3f 70 68 70|"; nocase; content:"unlink(__FILE__)"; nocase; distance:0; within:100; sid:9000004; rev:1;)
```

注意：
- content 中的特殊字符（如 `|`、`"`）需要用管道符十六进制编码，例如 `|3c 3f 70 68 70|` 表示 `<?php`。
- **十六进制编码规范**：`|...|` 内的每个字节必须是 **2 位**十六进制，用空格分隔。禁止单 digit（如 `|a|` 应写 `|0a|` 或 `|61|`）或混用 ASCII（如 `|3c 3f php|` 应写 `|3c 3f 70 68 70|`）。无效的 hex 会导致规则加载失败。
- 上述示例前两条使用 `any` 作为源地址，可同时覆盖外网攻击和内网横向移动，适用于攻击特征明确的场景。
- 前三条示例的攻击特征在 URL 中，使用 `http.uri` sticky buffer；第四条的 `<?php` 在 POST body 中，使用 `http.request_body`。

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
