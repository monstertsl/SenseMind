"""响应形态适配工具。

部分设备的 WebUI 接口不是纯 JSON：token 被塞在 JSON 之前的前缀里
（如天融信 `?[TOKEN}?{...}`），必须先切出 token 再解析剩余部分。
"""

import json
from typing import Optional, Tuple

import httpx

from .errors import DeviceError

TOKEN_PREFIX_START = "?["
TOKEN_PREFIX_END = "}?"


def split_token_prefix(text: str) -> Tuple[Optional[str], str]:
    """返回 (token, 剩余正文)；无前缀时 token 为 None。"""
    if TOKEN_PREFIX_START not in text:
        return None, text
    _, tail = text.split(TOKEN_PREFIX_START, 1)
    if TOKEN_PREFIX_END not in tail:
        return None, text
    token, body = tail.split(TOKEN_PREFIX_END, 1)
    return token.strip(), body


def json_body(response: httpx.Response, *, code: str = "bad_response") -> dict:
    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError):
        raise DeviceError(code, f"响应不是有效 JSON（HTTP {response.status_code}）") from None
    if not isinstance(payload, dict):
        raise DeviceError(code, "响应不是 JSON 对象")
    return payload


def json_after_token(response: httpx.Response, *, code: str = "bad_response") -> Tuple[Optional[str], dict]:
    """先切 `?[token}?` 前缀再解析 JSON，用于 WebUI 表单类接口。"""
    token, body = split_token_prefix(response.text)
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise DeviceError(code, f"响应正文不是有效 JSON（HTTP {response.status_code}）") from None
    if not isinstance(payload, dict):
        raise DeviceError(code, "响应正文不是 JSON 对象")
    return token, payload
