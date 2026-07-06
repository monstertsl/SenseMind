"""HTTP 响应体解码工具

Suricata 的 http-body-printable 选项仅保留可打印 ASCII 字符，
中文等多字节字符会被替换为"."。

启用 http-body: yes 后，Suricata 额外输出 Base64 编码的完整响应体
（http_response_body / http_request_body 字段），包含原始 UTF-8 字节。

本模块优先解码 Base64 版本以保留中文，解码失败时回退到 printable 版本。
"""

import base64
import logging

logger = logging.getLogger(__name__)


def decode_http_body(http_obj: dict, field: str = "http_response_body") -> str:
    """从 Suricata http 对象中提取并解码响应体/请求体

    优先级：
    1. http_response_body（Base64 编码，含完整原始字节）→ 解码为 UTF-8
    2. http_response_body_printable（可打印格式，中文被替换为.）

    Args:
        http_obj: Suricata eve 事件中的 http 子对象
        field: 字段名前缀，"http_response_body" 或 "http_request_body"

    Returns:
        解码后的文本，无数据返回空字符串
    """
    if not http_obj or not isinstance(http_obj, dict):
        return ""

    # 1. 优先尝试 Base64 解码（完整原始字节，含中文）
    b64_body = http_obj.get(field, "")
    if b64_body:
        try:
            raw_bytes = base64.b64decode(b64_body)
            # 尝试 UTF-8 解码（Suricata body 通常是 UTF-8 编码的文本）
            text = raw_bytes.decode("utf-8", errors="replace")
            # 清理：去除 NULL 字符等控制字符，保留换行和可打印字符
            text = _clean_body_text(text)
            if text.strip():
                return text
        except Exception as e:
            logger.debug("Base64 解码 %s 失败: %s", field, e)

    # 2. 回退到 printable 版本（中文被替换为.）
    printable_field = f"{field}_printable"
    return http_obj.get(printable_field, "")


def _clean_body_text(text: str) -> str:
    """清理响应体文本：去除控制字符，保留换行和可打印字符"""
    if not text:
        return ""
    # 保留换行符、回车符、制表符和所有可打印字符（含中文等多字节字符）
    # 去除 NULL 等不可见控制字符
    cleaned = []
    for ch in text:
        if ch in ("\n", "\r", "\t"):
            cleaned.append(ch)
        elif ord(ch) >= 32:
            cleaned.append(ch)
    return "".join(cleaned)
