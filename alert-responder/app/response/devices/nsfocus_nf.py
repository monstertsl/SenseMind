"""绿盟 NF 防火墙设备脚本（一个设备一个文件）。

认证是**静态 API Token**（Web 界面「系统管理 → API 管理」生成，长期有效、无登录换会话），
放在请求头 `Authorization: <token>`；API 端口默认 8081，前缀固定 `/north/nf`。

黑名单落点 = 策略配置 → 全局黑白名单 → 黑名单（`/north/nf/strategy/globalWb/blist`）：

- 查：`GET  .../blist/info/?size=&page=&search=`
- 新建：`POST .../blist/configuration/`，`action=create`
- 删除：`POST .../blist/delete/`，`{"id": [...]}`

响应统一是 `{"status": 2000, "module": "NF", "message": ..., "result": ...}`，
`status` 有 int 2000 与字符串 "2000" 两种形态，判定时统一转字符串比较。
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
    "key": "nsfocus_nf",
    "display_name": "绿盟 NF 防火墙",
    "schema_version": 1,
    "order": 4,
    "config_schema": [
        {
            "name": "base_url",
            "label": "管理地址",
            "type": "url",
            "required": True,
            "placeholder": "https://10.0.0.1:8081",
            "help": "含协议与 API 端口（官方默认 8081）",
        },
        {
            "name": "api_token",
            "label": "API Token",
            "type": "password",
            "required": True,
            "secret": True,
            "help": "设备 Web 界面「系统管理 → API 管理」生成的 Token",
        },
    ],
    # 接口带 ipv6 参数，未经真机验证前不声明能力
    "capabilities": {"ipv6": False},
}

log = logger("nsfocus_nf")

API_PREFIX = "/north/nf/strategy/globalWb/blist"
INFO_PATH = f"{API_PREFIX}/info/"
CONFIG_PATH = f"{API_PREFIX}/configuration/"
DELETE_PATH = f"{API_PREFIX}/delete/"
SUCCESS_STATUS = "2000"
BLACK_TYPE = "sourceIp"  # 封源地址（封目的地址用 destIp）
PROTOCOL = "any"
PAGE_ALL = -1
PAGE_SIZE = 100


def _client(cfg: dict):
    token = str(cfg.get("api_token") or "").strip()
    if not token:
        raise DeviceError("config_invalid", "缺少 API Token", retryable=False)
    return http_client(
        cfg,
        headers={"Authorization": token, "Content-Type": "application/json"},
    )


def _request(client, method: str, path: str, *, params=None, json=None, action: str):
    response = send(client, method, path, params=params, json=json)
    if response.status_code >= 400:
        raise status_error(response, message=f"{action}请求被拒绝")
    payload = json_body(response)
    status = payload.get("status")
    if str(status) != SUCCESS_STATUS:
        reason = payload.get("message") or status or "设备未返回原因"
        raise DeviceError("vendor_rejected", f"{action}失败：{reason}", retryable=False)
    return payload


def _query(client, *, search: str = "", page_all: bool = False):
    """返回 (list, total)；page_all 时不分页（size=-1）。"""
    params = {"size": PAGE_ALL if page_all else PAGE_SIZE, "page": 1}
    if search:
        params["search"] = search
    payload = _request(client, "GET", INFO_PATH, params=params, action="查询黑名单")
    result = payload.get("result") or {}
    rows = result.get("list") or []
    return rows, result.get("total") or 0


def _entries(client, ip: str) -> list:
    """按 IP 精确取黑名单条目；`search` 语义未生效时回退全量比对。"""
    rows, total = _query(client, search=ip)
    hits = [row for row in rows if str(row.get("ip") or "") == ip]
    if hits or not total:
        return hits
    rows, _ = _query(client, page_all=True)
    return [row for row in rows if str(row.get("ip") or "") == ip]


def test_connection(cfg: dict) -> ProbeResult:
    client = _client(cfg)
    try:
        payload = _request(client, "GET", INFO_PATH, params={"size": 1, "page": 1}, action="校验 Token")
    finally:
        client.close()
    total = (payload.get("result") or {}).get("total") or 0
    return ProbeResult(ok=True, message=f"Token 校验通过（黑名单 {total} 条）")


def block(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    client = _client(cfg)
    try:
        if _entries(client, target):
            log.info("IP 已在黑名单，跳过：%s", target)
            return
        _request(
            client,
            "POST",
            CONFIG_PATH,
            json={
                "type": BLACK_TYPE,
                "ip": target,
                "protocol": PROTOCOL,
                "objectType": "ip",
                "port": "any",
                "is_time": "f",
                "status": True,
                "action": "create",
            },
            action="添加黑名单",
        )
        if not _entries(client, target):
            raise DeviceError(
                "block_not_effective",
                f"设备返回成功但黑名单未见 {target}",
                retryable=True,
            )
        log.info("已加入黑名单：%s", target)
    finally:
        client.close()


def unblock(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    client = _client(cfg)
    try:
        entries = _entries(client, target)
        if not entries:
            log.info("IP 不在黑名单，跳过：%s", target)
            return
        ids = [row.get("id") for row in entries if row.get("id") is not None]
        if not ids:
            raise DeviceError("vendor_rejected", f"黑名单条目缺少 id，无法删除：{target}", retryable=False)
        _request(client, "POST", DELETE_PATH, json={"id": ids}, action="删除黑名单")
        if _entries(client, target):
            raise DeviceError(
                "unblock_not_effective",
                f"设备返回成功但黑名单仍有 {target}",
                retryable=True,
            )
        log.info("已移出黑名单：%s", target)
    finally:
        client.close()


def list_blocked(cfg: dict) -> list:
    client = _client(cfg)
    try:
        rows, _ = _query(client, page_all=True)
    finally:
        client.close()
    ips = {str(row.get("ip") or "").strip() for row in rows}
    result = sorted(ip for ip in ips if ip)
    log.info("黑名单共 %s 条", len(result))
    return result
