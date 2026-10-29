"""SenseMind 设备脚本公共模块。

设备脚本（内置与用户上传同格式）只 import 本模块，不 import 其他脚本；
平台逻辑（数据库、任务、白名单、重试编排、封堵记录）全部在宿主进程，本模块不提供。
"""

from .client import (
    DEFAULT_TIMEOUT,
    check_ip,
    check_network,
    http_client,
    send,
    set_transport_factory,
    status_error,
)
from .crypto import aes_cbc_zero_base64
from .errors import DeviceError, ProbeResult
from .log import logger, mask, mask_config
from .parsing import json_after_token, json_body, split_token_prefix

# 脚本清单版本；接口不兼容变更时递增，registry 加载时校验
API_VERSION = 1

__all__ = [
    "API_VERSION",
    "DEFAULT_TIMEOUT",
    "DeviceError",
    "ProbeResult",
    "aes_cbc_zero_base64",
    "check_ip",
    "check_network",
    "http_client",
    "json_after_token",
    "json_body",
    "logger",
    "mask",
    "mask_config",
    "send",
    "set_transport_factory",
    "split_token_prefix",
    "status_error",
]
