"""深信服防火墙设备脚本（一个设备一个文件）。

调用顺序：登录换 token → token 放 cookie → whiteblacklist 增删查。
"""

import time
from contextlib import contextmanager

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
    "key": "sangfor_af",
    "display_name": "深信服 AF 防火墙",
    "schema_version": 1,
    "order": 2,
    "config_schema": [
        {
            "name": "base_url",
            "label": "管理地址",
            "type": "url",
            "required": True,
            "placeholder": "https://10.0.0.1:443",
            "help": "含协议，端口按设备实际填写",
        },
        {"name": "username", "label": "用户名", "type": "text", "required": True},
        {"name": "password", "label": "密码", "type": "password", "required": True, "secret": True},
        {
            "name": "namespace",
            "label": "命名空间",
            "type": "text",
            "default": "@namespace",
            "help": "默认 @namespace 即根系统，单机部署不用改；多虚拟系统时填实际命名空间",
        },
    ],
    "capabilities": {"ipv6": False},
}

log = logger("sangfor_af")
DEFAULT_NAMESPACE = "@namespace"
BLACK_DESCRIPTION = "SenseMind联动封禁"
LIST_PAGE_SIZE = 200
NOT_FOUND_CODE = 1004  # 设备的「资源不存在」语义码，比中文文案稳定
VERIFY_ATTEMPTS = 2  # 处置后回查次数：首次不符再等一下重查，避免设备侧延迟造成误判
VERIFY_INTERVAL = 0.4


def _namespace(cfg: dict) -> str:
    return str(cfg.get("namespace") or DEFAULT_NAMESPACE).strip() or DEFAULT_NAMESPACE


def _base_path(cfg: dict) -> str:
    return f"/api/v1/namespaces/{_namespace(cfg)}"


def _ensure_ok(payload: dict, response, action: str) -> None:
    """设备成功可能只体现在 message=="成功"，也可能带 code==0，两者皆无即失败。"""
    if payload.get("code") in (0, "0") or payload.get("message") == "成功":
        return
    raise DeviceError(
        "vendor_rejected",
        f"{action}失败：{payload.get('message') or '设备未返回原因'}",
        retryable=False,
        status=response.status_code,
    )


def _login(cfg: dict):
    client = http_client(cfg, headers={"Content-Type": "application/json; charset=UTF-8"})
    try:
        response = send(
            client,
            "POST",
            f"{_base_path(cfg)}/login",
            json={"name": cfg.get("username"), "password": cfg.get("password")},
        )
        if response.status_code >= 400:
            raise status_error(response, message="登录请求被拒绝")
        payload = json_body(response)
        _ensure_ok(payload, response, "登录")
        token = ((payload.get("data") or {}).get("loginResult") or {}).get("token")
        if not token:
            raise DeviceError("login_no_token", "登录成功但未返回 token", retryable=False)
    except BaseException:
        client.close()
        raise
    client.cookies.set("token", token)
    return client, token


def _logout(client, cfg: dict) -> None:
    try:
        send(client, "POST", f"{_base_path(cfg)}/logout")
    except Exception:
        log.warning("退出登录失败，忽略")
    finally:
        client.close()


@contextmanager
def _session(cfg: dict, ctx):
    """有 setup 提供的会话就复用，否则临时登录一次并在结束时退出。"""
    if ctx and ctx.get("client") is not None:
        yield ctx["client"]
        return
    client, _ = _login(cfg)
    try:
        yield client
    finally:
        _logout(client, cfg)


def setup(cfg: dict) -> dict:
    client, token = _login(cfg)
    return {"client": client, "token": token, "namespace": _namespace(cfg)}


def teardown(ctx) -> None:
    if not ctx:
        return
    client = ctx.get("client")
    if client is None:
        return
    namespace = ctx.get("namespace") or DEFAULT_NAMESPACE
    _logout(client, {"namespace": namespace})


def test_connection(cfg: dict) -> ProbeResult:
    setup_ctx = setup(cfg)
    teardown(setup_ctx)
    return ProbeResult(ok=True, message=f"登录成功（命名空间 {_namespace(cfg)}）")


def _is_blocked(entry: dict) -> bool:
    if not entry.get("enable") or entry.get("type") != "BLACK":
        return False
    url_type = entry.get("urlType")
    if url_type is not None:
        return url_type == "ip"
    # 部分固件不回 urlType，改用 domain 标记：0 表示非域名（即 IP 对象）。
    # 漏判会让「已存在」被当成「不在黑名单」，解封被跳过、封堵重复下发。
    return entry.get("domain") in (None, 0, "0", False)


def _is_not_found(payload: dict) -> bool:
    """设备用 code=1004 表示资源不存在；文案会随固件/语言变化，优先看语义码。"""
    try:
        return int(payload.get("code")) == NOT_FOUND_CODE
    except (TypeError, ValueError):
        return False


def _query_entry(client, cfg: dict, ip: str) -> dict | None:
    """查单 IP 条目：不存在（404 / code=1004 / 文案含「不存在」）时返回 None。"""
    response = send(client, "GET", f"{_base_path(cfg)}/whiteblacklist/{ip}")
    if response.status_code == 404:
        return None
    if response.status_code >= 400:
        raise status_error(response, message="查询黑名单失败")
    payload = json_body(response)
    if isinstance(payload, dict) and _is_not_found(payload):
        return None
    if "不存在" in response.text:
        return None
    data = payload.get("data") if isinstance(payload, dict) else None
    return data if isinstance(data, dict) else None


def _query_ip(client, cfg: dict, ip: str) -> bool:
    entry = _query_entry(client, cfg, ip)
    return bool(entry) and _is_blocked(entry)


def _verify(client, cfg: dict, ip: str, expect_blocked: bool) -> bool | None:
    """处置后回查设备侧状态：True 与预期一致，False 不一致，None 无法确认（查询异常）。"""
    for attempt in range(1, VERIFY_ATTEMPTS + 1):
        try:
            actual = _query_ip(client, cfg, ip)
        except Exception as exc:  # 复查失败不改写处置结论，只留痕
            log.warning("复查 %s 状态失败（第 %s 次）：%s", ip, attempt, exc)
            return None
        if actual == expect_blocked:
            return True
        if attempt < VERIFY_ATTEMPTS:
            time.sleep(VERIFY_INTERVAL)
    return False


def _require_effective(client, cfg: dict, ip: str, expect_blocked: bool) -> None:
    """设备返回成功后再回查确认；明确不符即判失败，避免「设备说成功但没生效」被记账为成功。"""
    verified = _verify(client, cfg, ip, expect_blocked=expect_blocked)
    action = "封禁" if expect_blocked else "解封"
    if verified is False:
        detail = "IP 不在黑名单" if expect_blocked else "IP 仍在黑名单"
        raise DeviceError(
            "block_not_effective" if expect_blocked else "unblock_not_effective",
            f"设备返回成功，但复查未生效（{action}后{detail}）",
            retryable=True,
        )
    if verified:
        log.info("%s成功并已复查：%s", action, ip)


def block(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    with _session(cfg, ctx) as client:
        if _query_ip(client, cfg, target):
            log.info("IP 已在黑名单，跳过：%s", target)
            return
        response = send(
            client,
            "POST",
            f"{_base_path(cfg)}/whiteblacklist",
            json={
                "type": "BLACK",
                "url": target,
                "enable": True,
                "description": BLACK_DESCRIPTION,
            },
        )
        if response.status_code >= 400:
            raise status_error(response, message="添加黑名单失败")
        _ensure_ok(json_body(response), response, "添加黑名单")
        _require_effective(client, cfg, target, expect_blocked=True)


def unblock(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    with _session(cfg, ctx) as client:
        if not _query_ip(client, cfg, target):
            log.info("IP 不在黑名单，跳过：%s", target)
            return
        response = send(client, "DELETE", f"{_base_path(cfg)}/whiteblacklist/{target}")
        if response.status_code >= 400:
            raise status_error(response, message="删除黑名单失败")
        _ensure_ok(json_body(response), response, "删除黑名单")
        _require_effective(client, cfg, target, expect_blocked=False)


def list_blocked(cfg: dict):
    blocked = []
    with _session(cfg, None) as client:
        page = 0
        total_pages = 1
        while page < total_pages:
            response = send(
                client,
                "GET",
                f"{_base_path(cfg)}/whiteblacklist",
                params={"type": "BLACK", "_length": LIST_PAGE_SIZE, "_start": page * LIST_PAGE_SIZE},
            )
            if response.status_code >= 400:
                raise status_error(response, message="查询黑名单列表失败")
            payload = json_body(response)
            _ensure_ok(payload, response, "查询黑名单列表")
            data = payload.get("data") or {}
            items = data.get("items") or []
            try:
                total_pages = int(data.get("totalPages") or 1)
            except (TypeError, ValueError):
                total_pages = 1
            log.info(
                "黑名单第 %s 页：_start=%s 返回 %s 条（totalPages=%s）",
                page + 1,
                page * LIST_PAGE_SIZE,
                len(items),
                total_pages,
            )
            for entry in items:
                if _is_blocked(entry) and entry.get("url") not in blocked:
                    blocked.append(entry.get("url"))
            page += 1
    log.info("黑名单共 %s 条", len(blocked))
    return blocked
