"""深信服防火墙设备脚本（一个设备一个文件）。

接口依据 docs/sangfor_firewall/ 的官方示例：
登录换 token → token 放 cookie → whiteblacklist 增删查。
"""

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
    "display_name": "深信服防火墙",
    "schema_version": 1,
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
    return (
        bool(entry.get("enable"))
        and entry.get("type") == "BLACK"
        and entry.get("urlType") == "ip"
    )


def _query_ip(client, cfg: dict, ip: str) -> bool:
    response = send(client, "GET", f"{_base_path(cfg)}/whiteblacklist/{ip}")
    if response.status_code == 404:
        return False
    if response.status_code >= 400:
        raise status_error(response, message="查询黑名单失败")
    if "不存在" in response.text:
        return False
    payload = json_body(response)
    data = payload.get("data")
    if not isinstance(data, dict):
        return False
    return _is_blocked(data)


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
            for entry in data.get("items") or []:
                if _is_blocked(entry) and entry.get("url") not in blocked:
                    blocked.append(entry.get("url"))
            try:
                total_pages = int(data.get("totalPages") or 1)
            except (TypeError, ValueError):
                total_pages = 1
            page += 1
    return blocked
