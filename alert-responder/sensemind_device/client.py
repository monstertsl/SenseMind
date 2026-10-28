"""统一的 HTTP 客户端与 IP 校验。

平台字段（timeout_seconds / verify_tls / ca_cert_pem / max_concurrency）由这里统一消费，
设备脚本不要再自己处理超时与 TLS，否则会出现「某个调用点忘了带校验」的漏口。
"""

import ipaddress
import ssl
from typing import Optional

import httpx

from .errors import DeviceError

DEFAULT_TIMEOUT = 10.0

# 仅测试使用：注入 MockTransport 等替身，正常运行时保持 None
_transport_factory = None


def set_transport_factory(factory) -> None:
    global _transport_factory
    _transport_factory = factory


def _ssl_context(cfg: dict):
    if not cfg.get("verify_tls", False):
        return False
    ca_pem = cfg.get("ca_cert_pem")
    if ca_pem:
        return ssl.create_default_context(cadata=ca_pem)
    return ssl.create_default_context()


def http_client(
    cfg: dict,
    *,
    cookies: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: Optional[float] = None,
) -> httpx.Client:
    base_url = str(cfg.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise DeviceError("config_invalid", "缺少管理地址", retryable=False)
    transport = _transport_factory(base_url) if _transport_factory else None
    return httpx.Client(
        base_url=base_url,
        timeout=timeout or float(cfg.get("timeout_seconds") or DEFAULT_TIMEOUT),
        verify=_ssl_context(cfg),
        transport=transport,
        cookies=cookies,
        headers=headers,
        follow_redirects=False,
    )


def send(client: httpx.Client, method: str, url: str, **kwargs) -> httpx.Response:
    """把传输层异常收敛成 DeviceError，避免各脚本自己 try/except 出不同语义。"""
    try:
        return client.request(method, url, **kwargs)
    except httpx.TimeoutException as exc:
        raise DeviceError("timeout", f"请求超时（{type(exc).__name__}）", retryable=True) from None
    except httpx.HTTPError as exc:
        raise DeviceError("network", f"网络错误（{type(exc).__name__}）", retryable=True) from None


def check_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise DeviceError("invalid_ip", f"非法 IP：{value}", retryable=False) from None


def check_network(value: str) -> str:
    try:
        return str(ipaddress.ip_network(str(value).strip(), strict=False))
    except ValueError:
        raise DeviceError("invalid_cidr", f"非法 IP/CIDR：{value}", retryable=False) from None


def status_error(response: httpx.Response, *, message: str = "") -> DeviceError:
    """HTTP 层失败分类：超时/5xx 可重试，4xx 视为配置或权限问题。"""
    status = response.status_code
    retryable = status >= 500 or status == 429
    return DeviceError(
        "http_error",
        message or f"设备返回 HTTP {status}",
        retryable=retryable,
        status=status,
    )
