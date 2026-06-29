"""LLM 响应 JSON 解析工具

兼容各类 AI 模型的输出格式差异：
- 纯 JSON
- markdown 代码块包裹的 JSON (```json ... ``` 或 ``` ... ```)
- JSON 前后有多余文字
- JSON 字段值带换行
- 部分 AI 会输出思考过程再输出 JSON
"""

import json
import re
import logging

logger = logging.getLogger(__name__)


def extract_json(text: str) -> dict | None:
    """从 LLM 响应文本中提取 JSON 对象

    按优先级依次尝试：
    1. 去除 markdown 代码块后直接解析
    2. 提取第一个 { 到最后一个 } 的内容
    3. 用正则匹配 ```json ... ``` 代码块
    4. 逐层匹配嵌套花括号

    Args:
        text: LLM 返回的原始文本

    Returns:
        解析后的 dict，失败返回 None
    """
    if not text:
        return None

    text = text.strip()

    # 0. 去除 Qwen3 等模型的思考模式输出块
    text = _strip_thinking_blocks(text)

    # 1. 去除 markdown 代码块后直接解析
    cleaned = _strip_markdown(text)
    result = _try_parse(cleaned)
    if result is not None:
        return result

    # 2. 提取第一个 { 到最后一个 } 的内容
    result = _extract_outermost_json(text)
    if result is not None:
        return result

    # 3. 正则匹配 ```json ... ``` 或 ``` ... ``` 代码块
    code_block = _extract_code_block(text)
    if code_block is not None:
        result = _try_parse(code_block)
        if result is not None:
            return result
        # 代码块内再尝试提取花括号
        result = _extract_outermost_json(code_block)
        if result is not None:
            return result

    # 4. 尝试修复截断的 JSON（LLM 输出被 max_tokens 截断时）
    result = _repair_truncated_json(text)
    if result is not None:
        return result

    logger.warning("JSON 提取失败，原始文本: %s", text[:300])
    return None


def _strip_markdown(text: str) -> str:
    """去除 markdown 代码块标记"""
    if not text.startswith("```"):
        return text
    lines = text.split("\n")
    # 去掉首行 ``` 或 ```json
    lines = lines[1:]
    # 去掉末尾 ```
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _strip_thinking_blocks(text: str) -> str:
    """去除 Qwen3/DeepSeek 等模型的思考模式输出块</think>"""
    # 移除完整的\s*', '', text, flags=re.DOTALL)
    # 移除未闭合的 <think> 块（思考被截断，后续才是正文）
    idx = text.find('</think>')
    if idx >= 0:
        text = text[idx + len('</think>'):].strip()
    return text.strip()


def _repair_truncated_json(text: str) -> dict | None:
    """尝试修复被 max_tokens 截断的 JSON

    LLM 输出可能因 token 限制被截断，导致 JSON 不完整。
    策略：找到第一个 { ，逐步补全缺失的引号和括号。
    """
    start = text.find("{")
    if start < 0:
        return None

    json_str = text[start:]

    # 去除末尾不完整的部分（截断在字段值中间）
    # 找到最后一个完整的 "key": "value" 或 "key": number 对
    # 策略：从末尾向前找最后一个完整的逗号或花括号
    last_complete = -1
    in_string = False
    escape = False

    for i in range(len(json_str)):
        c = json_str[i]
        if escape:
            escape = False
            continue
        if c == "\\":
            escape = True
            continue
        if c == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if c == ",":
            last_complete = i

    if last_complete > 0:
        json_str = json_str[:last_complete]

    # 补全缺失的右括号
    open_braces = 0
    open_brackets = 0
    in_str = False
    esc = False
    for c in json_str:
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            open_braces += 1
        elif c == "}":
            open_braces -= 1
        elif c == "[":
            open_brackets += 1
        elif c == "]":
            open_brackets -= 1

    # 补全
    json_str += "]" * max(open_brackets, 0)
    json_str += "}" * max(open_braces, 0)

    return _try_parse(json_str)


def _try_parse(text: str) -> dict | None:
    """尝试 json.loads，失败返回 None"""
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, TypeError):
        pass
    return None


def _extract_outermost_json(text: str) -> dict | None:
    """提取最外层花括号包围的 JSON

    处理 JSON 前后有文字、JSON 内部有嵌套花括号的情况。
    用栈匹配确保提取完整的 JSON 对象。
    """
    start = text.find("{")
    if start < 0:
        return None

    depth = 0
    in_string = False
    escape = False
    end = -1

    for i in range(start, len(text)):
        c = text[i]

        if escape:
            escape = False
            continue

        if c == "\\":
            escape = True
            continue

        if c == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i
                break

    if end < 0:
        return None

    json_str = text[start:end + 1]
    return _try_parse(json_str)


def _extract_code_block(text: str) -> str | None:
    """正则提取 markdown 代码块内容"""
    # 匹配 ```json ... ``` 或 ``` ... ```
    match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def extract_json_list(text: str) -> list | None:
    """从 LLM 响应文本中提取 JSON 数组

    与 extract_json 类似，但处理 [...] 数组格式。
    用于批量漏报分析的 LLM 响应解析。

    Returns:
        解析后的 list，失败返回 None
    """
    if not text:
        return None

    text = text.strip()
    text = _strip_thinking_blocks(text)

    # 去除 markdown 代码块后直接解析
    cleaned = _strip_markdown(text)
    try:
        data = json.loads(cleaned)
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, TypeError):
        pass

    # 提取最外层 [ 到匹配的 ]
    start = cleaned.find("[")
    if start < 0:
        return None

    depth = 0
    in_string = False
    escape = False
    end = -1

    for i in range(start, len(cleaned)):
        c = cleaned[i]
        if escape:
            escape = False
            continue
        if c == "\\":
            escape = True
            continue
        if c == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                end = i
                break

    if end < 0:
        return None

    try:
        data = json.loads(cleaned[start:end + 1])
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, TypeError):
        pass

    return None


def safe_parse_llm_response(text: str, fallback: dict = None) -> dict:
    """安全的 LLM 响应解析，带 fallback

    Args:
        text: LLM 返回的原始文本
        fallback: 解析失败时的默认值

    Returns:
        解析后的 dict，失败返回 fallback（默认空 dict）
    """
    result = extract_json(text)
    if result is not None:
        return result
    return fallback if fallback is not None else {}
