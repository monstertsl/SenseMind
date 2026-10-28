"""奇安信防火墙设备脚本（一个设备一个文件）。

接口依据 docs/qianxin_firewall/ 文档与参考实现的调用顺序：
/v1.0/login/ 取 `__s_sessionid__` cookie + `result.token`，业务走 /v1.0/rest/ 按
head.module + head.function 分发，结束 /v1.0/out/ 退登。
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
    "key": "qianxin_firewall",
    "display_name": "奇安信防火墙",
    "schema_version": 1,
    "config_schema": [
        {
            "name": "base_url",
            "label": "管理地址",
            "type": "url",
            "required": True,
            "placeholder": "https://10.0.0.1:8443",
            "help": "含协议，端口按设备实际填写",
        },
        {"name": "username", "label": "用户名", "type": "text", "required": True},
        {"name": "password", "label": "密码", "type": "password", "required": True, "secret": True},
    ],
    # 未实现 list_blocked：get_blacklist_config 的分页参数需真机核验后再开放
    "capabilities": {"ipv6": False},
}

log = logger("qianxin_firewall")
MODULE = "addr_blacklist"
# 写入「地址黑名单」（策略配置-黑白名单-地址黑名单），不用批量黑 IP 名单。
# 设备规格：地址黑名单上限 1000 条且添加接口不支持批量下发；超量场景需改走批量黑 IP。
BLACK_DESC = "SenseMind联动封禁"
NAME_PREFIX = "sm-"


def _first(payload):
    """rest 接口请求体是列表，响应可能是列表也可能单对象。"""
    if isinstance(payload, list):
        if not payload:
            raise DeviceError("empty_response", "设备返回空结果")
        return payload[0]
    return payload


def _head(payload, action: str):
    result = _first(payload)
    head = (result or {}).get("head") or {}
    if head.get("error_code") not in (0, "0", None):
        raise DeviceError(
            "vendor_rejected",
            f"{action}失败：{head.get('error_message') or head.get('error_code')}",
            retryable=False,
        )
    return result


def _rest(client, *, module: str, function: str, body: dict, action: str):
    response = send(
        client,
        "POST",
        "/v1.0/rest/",
        json=[{"head": {"module": module, "function": function}, "body": body}],
    )
    if response.status_code >= 400:
        raise status_error(response, message=f"{action}请求被拒绝")
    return _head(json_body(response), action)


def _login(cfg: dict):
    client = http_client(cfg, headers={"Content-Type": "application/json; charset=UTF-8"})
    try:
        response = send(
            client,
            "POST",
            "/v1.0/login/",
            json={"username": cfg.get("username"), "password": cfg.get("password")},
        )
        if response.status_code >= 400:
            raise status_error(response, message="登录请求被拒绝")
        payload = json_body(response)
        head = payload.get("head") or {}
        token = (payload.get("result") or {}).get("token")
        if not token:
            reason = head.get("error_message") or "登录未返回 token"
            raise DeviceError("login_failed", str(reason), retryable=False)
        session_id = response.cookies.get("__s_sessionid__") or client.cookies.get("__s_sessionid__")
    except BaseException:
        client.close()
        raise
    if session_id:
        client.cookies.set("__s_sessionid__", session_id)
    client.cookies.set("token", token)
    return client


def _logout(client, cfg: dict) -> None:
    try:
        send(client, "POST", "/v1.0/out/", json={"username": cfg.get("username")})
    except Exception:
        log.warning("退出登录失败，忽略")
    finally:
        client.close()


@contextmanager
def _session(cfg: dict, ctx):
    if ctx and ctx.get("client") is not None:
        yield ctx["client"]
        return
    client = _login(cfg)
    try:
        yield client
    finally:
        _logout(client, cfg)


def setup(cfg: dict) -> dict:
    client = _login(cfg)
    return {"client": client}


def teardown(ctx) -> None:
    if not ctx or ctx.get("client") is None:
        return
    _logout(ctx["client"], {})


def test_connection(cfg: dict) -> ProbeResult:
    session = setup(cfg)
    teardown(session)
    return ProbeResult(ok=True, message="登录成功")


def _entries(client, ip: str) -> list:
    """按 IP 查地址黑名单；search_key 支持模糊匹配，故精确比对起止地址。"""
    result = _rest(
        client,
        module=MODULE,
        function="get_blacklist_config",
        body={"addr_blacklist_cp": {"search_key": ip, "is_detail": "true"}},
        action="查询地址黑名单",
    )
    rows = (result or {}).get("data") or []
    return [
        row
        for row in rows
        if str(row.get("ip_start") or "") == ip and str(row.get("ip_end") or "") == ip
    ]


def block(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    with _session(cfg, ctx) as client:
        if _entries(client, target):
            log.info("IP 已在地址黑名单，跳过：%s", target)
            return
        _rest(
            client,
            module=MODULE,
            function="add_blacklist_ip_web",
            body={
                "addr_blacklist_cp": {
                    "blacklist_cp": [
                        {
                            "name": f"{NAME_PREFIX}{target}",
                            "type": "host",
                            "ip_start": target,
                            "ip_end": target,
                            "enable": "enable",
                            "desc": BLACK_DESC,
                            "schedule": "",
                        }
                    ]
                }
            },
            action="添加地址黑名单",
        )


def unblock(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    with _session(cfg, ctx) as client:
        entries = _entries(client, target)
        if not entries:
            log.info("IP 不在地址黑名单，跳过：%s", target)
            return
        # 删除接口按条目的起止地址匹配（传 name/id 都会返回成功但不生效）
        for entry in entries:
            _rest(
                client,
                module=MODULE,
                function="del_blacklist_by_id",
                body={
                    "addr_blacklist_cp": {
                        "blacklist_cp": [
                            {"ip_start": entry.get("ip_start"), "ip_end": entry.get("ip_end")}
                        ]
                    }
                },
                action="删除地址黑名单",
            )
