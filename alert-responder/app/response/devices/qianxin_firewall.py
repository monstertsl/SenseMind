"""奇安信防火墙设备脚本（一个设备一个文件）。

调用顺序：/v1.0/login/ 取 `__s_sessionid__` cookie + `result.token`，业务走 /v1.0/rest/ 按
head.module + head.function 分发，结束 /v1.0/out/ 退登。
封禁落点是「人工处置 → 网络连接」（module=threat_disposal）：地址黑名单只对源地址生效，
故每个 IP 下发两条处置项——sip 为该 IP 与 dip 为该 IP 各一条。
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
    "order": 1,
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
    # 未实现 list_blocked：需分页遍历全部处置项，真机核验后再开放
    "capabilities": {"ipv6": False},
}

log = logger("qianxin_firewall")
MODULE = "threat_disposal"
SOURCE = "manual"
DATATYPE = "connection"
# 处置时效取「永久」，解封由平台侧删除处置项完成
BLOCK_TIMEOUT = "forever"
# 处置项状态：封禁幂等只看「处置中」，解封要连「待响应」一起清（两者都可直接删除）
BLOCK_STATUSES = ("block",)
PENDING_STATUSES = ("block", "undisposed")
# 查询条件里的空值/0 都表示 any，比对时必须当作「不限」处理
ANY_TOKENS = ("", "0", "any")
PAGE_SIZE = 100
MAX_PAGES = 10


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
        reason = head.get("error_string") or head.get("error_message") or head.get("error_code")
        raise DeviceError("vendor_rejected", f"{action}失败：{reason}", retryable=False)
    return result


def _int(value, default: int = -1) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _rest(client, *, function: str, body: dict, action: str, page: int = 0):
    head = {"module": MODULE, "function": function}
    if page:
        head["page_index"] = page
        head["page_size"] = PAGE_SIZE
    response = send(
        client,
        "POST",
        "/v1.0/rest/",
        json=[{"head": head, "body": body}],
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


def _is_any(value) -> bool:
    return str(value or "").strip().lower() in ANY_TOKENS


def _direction(row: dict, statuses=BLOCK_STATUSES) -> str:
    """处置项方向：sip 有值且 dip 为空 → 源；dip 有值且 sip 为空 → 目的。

    statuses 限定参与判定的状态：封禁幂等只看「处置中」，解封要连「待响应」一起认。
    """
    if str(row.get("datatype") or "") != DATATYPE:
        return ""
    if str(row.get("status") or "") not in statuses:
        return ""
    if str(row.get("ipv4") or "yes") != "yes":
        return ""
    sip = str(row.get("sip") or "").strip()
    dip = str(row.get("dip") or "").strip()
    if sip and _is_any(dip):
        return "src"
    if dip and _is_any(sip):
        return "dst"
    return ""


def _matches(row: dict, ip: str, statuses=BLOCK_STATUSES) -> bool:
    direction = _direction(row, statuses)
    if not direction:
        return False
    value = row.get("sip") if direction == "src" else row.get("dip")
    return str(value or "").strip() == ip


def _rows(client, searchkey: str) -> list:
    rows = []
    page = 1
    while page <= MAX_PAGES:
        result = _rest(
            client,
            function="get_threat_disposal",
            body={
                "threat_disposal_cfg_ext": {
                    "operation": "",
                    "is_later": "no",
                    "disposal_filter": {
                        "status": "",
                        "searchkey": searchkey,
                        "expired": "0",
                        "datatype": "",
                        "source": "",
                    },
                }
            },
            action="查询人工处置",
            page=page,
        )
        batch = (result or {}).get("data") or []
        rows.extend(batch)
        total = _int(((result or {}).get("head") or {}).get("total"))
        if len(batch) < PAGE_SIZE or (total >= 0 and len(rows) >= total):
            break
        page += 1
    return rows


def _find(client, ip: str, statuses=BLOCK_STATUSES) -> list:
    """找出该 IP 的处置项。

    searchkey 是模糊查询、未必覆盖目的地址方向，未命中时退化为全量比对。
    """
    hits = [row for row in _rows(client, ip) if _matches(row, ip, statuses)]
    if not hits:
        hits = [row for row in _rows(client, "") if _matches(row, ip, statuses)]
    return hits


def _block_rule(ip: str, direction: str) -> dict:
    """单条处置项：只填一个方向，另一方向留空即 any。"""
    rule = {
        "ipv4": "yes",
        "timeout": BLOCK_TIMEOUT,
        "action": "block",
        "source": SOURCE,
        "datatype": DATATYPE,
    }
    rule["sip" if direction == "src" else "dip"] = ip
    return rule


def _record_rule(row: dict, raw: bool = False) -> dict:
    """按五元组定位一条处置记录（撤销与删除共用）。

    默认与添加时同构（只带方向地址），部分固件要求把端口、协议等原值一并回传，
    此时用 raw=True 走「查询结果原样回传」的形态。
    """
    rule = {
        "ipv4": str(row.get("ipv4") or "yes"),
        "source": str(row.get("source") or SOURCE),
        "datatype": str(row.get("datatype") or DATATYPE),
    }
    if raw:
        for key in ("sip", "sport", "dip", "dport", "proto"):
            rule[key] = str(row.get(key) or "").strip()
        if row.get("dispose_id"):
            rule["dispose_id"] = str(row["dispose_id"])
        rule["action"] = str(row.get("action") or "block")
        rule["timeout"] = str(row.get("timeout") or BLOCK_TIMEOUT)
        return rule
    direction = _direction(row, PENDING_STATUSES) or ("src" if str(row.get("sip") or "").strip() else "dst")
    value = row.get("sip") if direction == "src" else row.get("dip")
    rule["sip" if direction == "src" else "dip"] = str(value or "").strip()
    return rule


def _dispose(client, rows: list, *, function: str, action: str, operation: str = "") -> None:
    """下发撤销/删除：先按添加同构，被固件拒绝（error_code 非 0）再按查询原值重试一次。"""
    for raw in (False, True):
        ext = {"is_later": "no", "threat_disposal_cfg": [_record_rule(row, raw=raw) for row in rows]}
        if operation:
            ext["operation"] = operation
        try:
            _rest(client, function=function, body={"threat_disposal_cfg_ext": ext}, action=action)
            return
        except DeviceError as exc:
            if raw or exc.code != "vendor_rejected":
                raise
            log.warning("%s被拒（%s），按设备原值重试", action, exc)


def block(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    with _session(cfg, ctx) as client:
        existing = {_direction(row) for row in _find(client, target)}
        missing = [direction for direction in ("src", "dst") if direction not in existing]
        if not missing:
            log.info("IP 已有源地址与目的地址处置，跳过：%s", target)
            return
        _rest(
            client,
            function="add_threat_disposal",
            body={
                "threat_disposal_cfg_ext": {
                    "is_later": "no",
                    "threat_disposal_cfg": [_block_rule(target, d) for d in missing],
                }
            },
            action="添加人工处置",
        )


def unblock(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    with _session(cfg, ctx) as client:
        hits = _find(client, target, statuses=PENDING_STATUSES)
        if not hits:
            log.info("IP 无人工处置记录，跳过：%s", target)
            return
        active = [row for row in hits if _direction(row, BLOCK_STATUSES)]
        pending = [row for row in hits if not _direction(row, BLOCK_STATUSES)]
        # 处置中的记录直接删除即解除阻断；删除被拒才退回撤销（撤销会留下待响应记录）
        if active:
            try:
                _dispose(client, active, function="del_threat_disposal", action="删除人工处置记录")
            except DeviceError as exc:
                if exc.code != "vendor_rejected":
                    raise
                log.warning("删除人工处置记录被拒（%s），改走撤销：%s", exc, target)
                _dispose(
                    client, active, function="set_threat_disposal", action="撤销人工处置", operation="revoke"
                )
                log.warning("已撤销处置，记录会以「待响应」状态留在列表：%s", target)
        # 已是「待响应」的历史记录同样直接删，不做「恢复处置再删」那种反复改状态的绕路
        if pending:
            try:
                _dispose(client, pending, function="del_threat_disposal", action="删除待响应处置记录")
                log.info("已删除待响应记录 %s 条：%s", len(pending), target)
            except DeviceError as exc:
                if exc.code != "vendor_rejected":
                    raise
                log.warning("待响应记录删除被拒（%s），需在设备 WebUI 手工处理：%s", exc, target)
