"""示例设备脚本：把 IP 写入厂商设备的黑名单表。

使用步骤
1. 下载本文件，改名为 `<vendor>_device.py`，并把 MANIFEST["key"] 改成同名（去掉 `.py`）。
2. 按厂商接口改 `BLACKLIST_PATH` 以及 block/unblock 里的请求体字段。
3. 通过「添加联动设备 → 上传设备脚本」上传，上传后设备类型下拉里会多出 MANIFEST["display_name"]。

约束
- 文件名（去掉 .py）必须与 MANIFEST["key"] 完全一致，且只能是小写字母开头的字母/数字/下划线。
- 必须实现 `block(ip, cfg, ctx=None)` 与 `unblock(ip, cfg, ctx=None)`；`test_connection` 与 `list_blocked` 可选。
- 网络请求统一走 `sensemind_device` 提供的 `http_client` / `send`，超时、代理、证书校验由平台配置统一管理。
- 上传的脚本会被平台导入执行，仅管理员可上传，且只能导入白名单内的模块（见 DEVICE_INTEGRATION.md 第二节），
  httpx / os / sys / subprocess / __future__ 等一律拒绝。
"""

from sensemind_device import (
    DeviceError,
    ProbeResult,
    check_ip,
    http_client,
    json_body,
    logger,
    send,
    status_error,
)

MANIFEST = {
    "key": "example_vendor",
    "display_name": "示例厂商防火墙",
    "schema_version": 1,
    # 下拉展示顺序，小的在前；未声明按 100 排
    "order": 90,
    "config_schema": [
        {
            "name": "base_url",
            "label": "管理地址",
            "type": "url",
            "required": True,
            "placeholder": "https://10.0.0.1:8443",
            "help": "含协议与端口，例如 https://10.0.0.1:8443",
        },
        {
            "name": "username",
            "label": "用户名",
            "type": "text",
            "required": True,
        },
        {
            "name": "password",
            "label": "密码",
            "type": "password",
            "required": True,
            "secret": True,
            "help": "保存后前端不再回显，编辑时留空表示沿用旧值",
        },
    ],
    "capabilities": {"ipv6": False},
}

log = logger("example_vendor")

BLACKLIST_PATH = "/api/blacklist"


def _client(cfg: dict):
    username = str(cfg.get("username") or "").strip()
    password = cfg.get("password") or ""
    if not username or not password:
        raise DeviceError("config_invalid", "缺少用户名或密码", retryable=False)
    client = http_client(cfg, headers={"Content-Type": "application/json"})
    # 设备要求先登录换 token 时：在这里发登录请求，成功后把 token 写进 client.headers
    return client


def test_connection(cfg: dict) -> ProbeResult:
    client = _client(cfg)
    try:
        response = send(client, "GET", BLACKLIST_PATH)
    finally:
        client.close()
    if response.status_code >= 400:
        raise status_error(response, message="黑名单接口不可用")
    return ProbeResult(ok=True, message="连接正常，黑名单接口可读")


def block(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    client = _client(cfg)
    try:
        response = send(client, "POST", BLACKLIST_PATH, json={"ip": target, "action": "add"})
        if response.status_code >= 400:
            raise status_error(response, message="添加黑名单失败")
        payload = json_body(response)
        if str(payload.get("code")) != "0":
            raise DeviceError(
                "vendor_rejected",
                f"添加黑名单失败：{payload.get('message') or payload.get('code')}",
                retryable=False,
            )
        log.info("已加入黑名单：%s", target)
    finally:
        client.close()


def unblock(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    client = _client(cfg)
    try:
        response = send(client, "POST", BLACKLIST_PATH, json={"ip": target, "action": "remove"})
        if response.status_code >= 400:
            raise status_error(response, message="移除黑名单失败")
        payload = json_body(response)
        if str(payload.get("code")) != "0":
            raise DeviceError(
                "vendor_rejected",
                f"移除黑名单失败：{payload.get('message') or payload.get('code')}",
                retryable=False,
            )
        log.info("已移出黑名单：%s", target)
    finally:
        client.close()


def list_blocked(cfg: dict) -> list:
    """可选：返回设备侧黑名单 IP 列表。不实现则平台标记该设备类型不支持回读。"""
    client = _client(cfg)
    try:
        response = send(client, "GET", BLACKLIST_PATH)
    finally:
        client.close()
    if response.status_code >= 400:
        raise status_error(response, message="读取黑名单失败")
    payload = json_body(response)
    items = payload.get("data") or []
    if not isinstance(items, list):
        return []
    ips = []
    for item in items:
        value = item.get("ip") if isinstance(item, dict) else item
        if value:
            ips.append(str(value))
    return sorted(ips)
