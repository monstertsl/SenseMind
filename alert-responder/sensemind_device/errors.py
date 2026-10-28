"""设备脚本共用的结果与异常类型。"""

from dataclasses import dataclass, field
from typing import Optional


class DeviceError(Exception):
    """设备对接失败。

    retryable=True 仅用于网络/超时/5xx 这类重放可能成功的失败；
    厂商业务码拒绝必须为 False，否则重试只会重复打设备。
    """

    def __init__(
        self,
        code: str,
        message: str = "",
        retryable: bool = False,
        *,
        status: Optional[int] = None,
    ) -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.retryable = retryable
        self.status = status

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


@dataclass(frozen=True)
class ProbeResult:
    """连接测试结果，直接用于「添加设备-测试连接」的回显。"""

    ok: bool
    message: str = ""
    detail: dict = field(default_factory=dict)
