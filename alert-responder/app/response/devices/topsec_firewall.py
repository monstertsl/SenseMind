"""天融信防火墙设备脚本（一个设备一个文件）。

调用约定：

- 登录首选 `POST /home/restLogin/`：表单 `name` + `password` + `ngtosAuth`，两者都用 AES-CBC
  加密（密钥/偏移量均为 16 个 `1`、零填充、输出 base64），`ngtosAuth` 是加密后的明文长度；
  token 由响应的 `tokens` 数组给出而非响应前缀。
- 老固件没有该接口（HTTP 404），此时改走 `POST /home/login/addNoCode/`：`name` + `password` +
  `pwdlen`，密码用 AES-CBC 但密钥/偏移量换成 `ngfwrestapilogin`，`pwdlen` 是明文长度。
  响应正文是 base64 JSON，`data.authid` 即 userMark，`data.secret` 参与 codeRun。
- 除登录外每个接口都必须带登录返回的 Cookie、`Referer` 与 `Content-Type` 表头。
- `token`：响应里 `?[` 与 `}?` 之间的字符串，每次请求都会换新的，下一次请求必须用最新的。
- `codeRun` = `md5(secret + token + url + commands 的 JSON)`，JSON 按设备侧的数组形态
  （`[{"pf_blacklist_add":{"sip":"1.1.1.1"}}]`）序列化，不能带数字键。
- 参数键保留字面量：`commands[0][pf_blacklist_add][sip]` 里的 `[` `]` 不能百分号编码，
  否则设备解析不出命令，返回「无效输入，分析错误」。
- 黑名单落点：`资源管理 → 黑名单传播`（`blackListSpread`），按五元组下发与删除。
"""

import base64
import hashlib
import ipaddress
import json
from contextlib import contextmanager
from urllib.parse import quote_plus

from sensemind_device import (
    DeviceError,
    ProbeResult,
    aes_cbc_zero_base64,
    check_ip,
    http_client,
    logger,
    send,
    status_error,
)

MANIFEST = {
    "key": "topsec_firewall",
    "display_name": "天融信防火墙",
    "schema_version": 1,
    "order": 3,
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
        {
            "name": "password",
            "label": "密码",
            "type": "password",
            "required": True,
            "secret": True,
            "help": "登录密码明文，脚本按设备要求自行加密",
        },
    ],
    # 未实现 list_blocked：搜索接口未提供稳定分页，需真机核验后再开放
    "capabilities": {"ipv6": False},
}

log = logger("topsec_firewall")

LOGIN_PATH = "/home/login/addNoCode/"
LOGOUT_PATH = "/home/index/logout/"
RESTLOGOUT_PATH = "/home/restLogout/"
# 静态黑名单（WebUI：安全策略 → 黑名单 → 静态黑名单）：查/加在 blackWhite 模块，删除在 blackListSpread
BLACKLIST_SEARCH = "/home/default/blackWhite/addrStaticBlackSearch/"
BLACKLIST_ADD = "/home/default/blackWhite/whiteIpAdd/"
BLACKLIST_DELETE = "/home/default/blackListSpread/deleteLots/"
BLACKLIST_SHOW_ALL = "/home/default/blackListSpread/showAll/"
POLICY_GROUP = "/home/default/blackWhite/showPolicyGroup/"
# 源方向必须封住（只有它拦得住攻击源主动发来的流量）；目的方向尽力下发，
# 3.7 设备同一 IP 只允许一条记录，第二条会被拒，属设备限制而非失败
BLOCK_DIRECTIONS = ("src", "dst")
GROUP_NAME = "default_group"
BLOCK_COMMENT = "SenseMind联动封禁"

# 设备登录表单的口令加密参数（官方文档固定值）
LOGIN_AES_KEY = "ngfwrestapilogin"
LOGIN_AES_IV = "ngfwrestapilogin"
RESTLOGIN_PATH = "/home/restLogin/"
# restLogin 的口令与长度加密固定用 16 个 1（官方示例注释）
REST_LOGIN_AES_KEY = "1111111111111111"
REST_LOGIN_AES_IV = "1111111111111111"


def _split_token(text: str) -> tuple:
    """响应形如 `?[TOKEN}?<body>`；无前缀时 token 为空、body 为原文。"""
    if "?[" not in text:
        return "", text
    tail = text.split("?[", 1)[1]
    if "}?" not in tail:
        return "", text
    token, body = tail.split("}?", 1)
    return token.strip(), body.strip()


def _decode_login_body(body: str) -> dict:
    """登录响应是 base64 JSON；个别版本直接返回 JSON，两种都兼容。"""
    text = body.strip()
    try:
        decoded = base64.b64decode(text).decode("utf-8")
    except Exception:
        decoded = text
    try:
        payload = json.loads(decoded)
    except ValueError:
        raise DeviceError("bad_response", "登录响应不是有效 JSON", retryable=False) from None
    return payload if isinstance(payload, dict) else {}


def _json_body(body: str, action: str) -> dict:
    try:
        payload = json.loads(body)
    except ValueError:
        raise DeviceError("bad_response", f"{action}响应不是有效 JSON", retryable=False) from None
    return payload if isinstance(payload, dict) else {}


def _flatten(name: str, value, out: dict) -> None:
    """嵌套命令字典 → `commands[0][pf_blacklist_add][sip]=1.1.1.1` 形式的表单字段。"""
    if isinstance(value, dict):
        for key, item in value.items():
            _flatten(f"{name}[{key}]", item, out)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _flatten(f"{name}[{index}]", item, out)
        return
    if value is None:
        out[name] = ""
    elif isinstance(value, bool):
        out[name] = "true" if value else "false"
    else:
        out[name] = str(value)


def _build_query(params: dict) -> str:
    """拼 query / 表单串：键保持原样，只对值编码。

    设备按 `commands[0][pf_blacklist_add][sip]` 字面解析参数，键里的 `[` `]` 一旦被
    百分号编码就解析不出命令，返回「无效输入，分析错误」。
    """
    return "&".join(f"{key}={quote_plus(str(value))}" for key, value in params.items())


def _sign_value(value):
    """数字键字典还原成 JSON 数组。

    设备把 `commands[0][x][0]=v` 还原成 `[{"x":["v"]}]`，codeRun 也按数组算；
    命令里用 `{"0": ...}` 只是为了让 _flatten 能拼出带下标的字段名。
    """
    if isinstance(value, dict):
        if value and all(str(key).isdigit() for key in value):
            ordered = sorted(value, key=lambda key: int(str(key)))
            return [_sign_value(value[key]) for key in ordered]
        return {key: _sign_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sign_value(item) for item in value]
    return value


def _code_run(secret: str, token: str, url: str, commands: dict) -> str:
    serialized = json.dumps(_sign_value(commands), ensure_ascii=False, separators=(",", ":"))
    return hashlib.md5((secret + token + url + serialized).encode("utf-8")).hexdigest()


class _Session:
    """持有 cookie / userMark / secret / token 的会话，token 每次响应轮转。"""

    def __init__(self, client, token: str, user_mark: str, secret: str, rest_login: bool = False):
        self.client = client
        self.token = token
        self.user_mark = user_mark
        self.secret = secret
        self.rest_login = rest_login
        self.group_name = ""  # 首次封禁时从策略组接口取，避免把组名写死

    def _headers(self) -> dict:
        base = str(self.client.base_url).rstrip("/")
        return {
            "Referer": f"{base}/html/webui/home.html/?userMark={self.user_mark}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

    def _absorb(self, response) -> str:
        if response.status_code >= 400:
            raise status_error(response, message=f"设备返回 HTTP {response.status_code}")
        token, body = _split_token(response.text)
        if token:
            self.token = token
        return body

    def post(self, path: str, commands: dict) -> str:
        # token / codeRun 放 query、commands 放表单，且键不编码，与设备 WebUI 形态一致
        fields: dict = {}
        _flatten("commands", commands, fields)
        params: dict = {"userMark": self.user_mark}
        if self.token:
            params["token"] = self.token
        if self.secret:
            params["codeRun"] = _code_run(self.secret, self.token, path, commands)
        response = send(
            self.client,
            "POST",
            f"{path}?{_build_query(params)}",
            content=_build_query(fields).encode("utf-8"),
            headers=self._headers(),
        )
        return self._absorb(response)

    def get(self, path: str, commands: dict | None = None) -> str:
        params: dict = {"userMark": self.user_mark}
        if commands:
            _flatten("commands", commands, params)
        if self.token:
            params["token"] = self.token
        # 登出这类命令为空（`{}`）的请求同样要带 codeRun，故判 None 而不是真假
        if commands is not None and self.secret:
            params["codeRun"] = _code_run(self.secret, self.token, path, commands)
        response = send(self.client, "GET", f"{path}?{_build_query(params)}", headers=self._headers())
        return self._absorb(response)


def _session_parts(payload: dict) -> tuple:
    """从登录响应里取出 userMark 与 secret（两种登录方式字段位置不同）。"""
    data = payload.get("data")
    if payload.get("result") is not True:
        reason = data if isinstance(data, str) else "设备拒绝登录"
        raise DeviceError("login_failed", f"登录失败：{reason}", retryable=False)
    data = data if isinstance(data, dict) else {}
    user_mark = str(data.get("authid") or "").strip()
    if not user_mark:
        raise DeviceError("login_failed", "登录响应未返回 authid", retryable=False)
    secret = str(payload.get("secret") or data.get("secret") or "").strip()
    return user_mark, secret


def _session_from_restlogin(client, response) -> "_Session":
    """解析 `POST /home/restLogin/` 的响应：普通 JSON、token 在 `tokens` 数组里。"""
    if response.status_code >= 400:
        raise status_error(response, message="restLogin 请求被拒绝")
    token, body = _split_token(response.text)
    try:
        payload = json.loads(body)
    except ValueError:
        raise DeviceError("bad_response", "restLogin 响应不是有效 JSON", retryable=False) from None
    payload = payload if isinstance(payload, dict) else {}
    if not token:
        # 登录响应不带 token 前缀时，token 由 tokens 数组给出（取第 2 个）
        tokens = payload.get("tokens") or []
        token = str(tokens[1]) if len(tokens) > 1 else (str(tokens[0]) if tokens else "")
    user_mark, secret = _session_parts(payload)
    return _Session(client, token, user_mark, secret, rest_login=True)


def _login_addnocode(client, cfg: dict, password: str) -> "_Session":
    """老固件的 `POST /home/login/addNoCode/`：口令 AES-CBC（key/iv 均为 ngfwrestapilogin），另传明文长度。"""
    cipher = aes_cbc_zero_base64(password, LOGIN_AES_KEY, LOGIN_AES_IV)
    response = send(
        client,
        "POST",
        LOGIN_PATH,
        data={"name": cfg.get("username"), "password": cipher, "pwdlen": len(password)},
    )
    if response.status_code >= 400:
        raise status_error(response, message="登录请求被拒绝")
    token, body = _split_token(response.text)
    user_mark, secret = _session_parts(_decode_login_body(body))
    return _Session(client, token, user_mark, secret)


def _login(cfg: dict) -> _Session:
    """登录：3.7 起只提供 restLogin；老固件没有该接口（404）时退回 addNoCode。"""
    client = http_client(cfg)
    try:
        password = str(cfg.get("password") or "")
        cipher = aes_cbc_zero_base64(password, REST_LOGIN_AES_KEY, REST_LOGIN_AES_IV)
        length = aes_cbc_zero_base64(str(len(password)), REST_LOGIN_AES_KEY, REST_LOGIN_AES_IV)
        response = send(
            client,
            "POST",
            RESTLOGIN_PATH,
            data={"name": cfg.get("username"), "password": cipher, "ngtosAuth": length},
        )
        if response.status_code == 404:
            log.info("%s 不存在（HTTP 404），改试 %s", RESTLOGIN_PATH, LOGIN_PATH)
            return _login_addnocode(client, cfg, password)
        return _session_from_restlogin(client, response)
    except BaseException:
        client.close()
        raise


def _logout(session: _Session) -> None:
    try:
        # 两条登录线路的退登接口不同；命令为空（{}）也要带 codeRun，否则设备报 Parameter tampered
        session.get(RESTLOGOUT_PATH if session.rest_login else LOGOUT_PATH, {})
    except Exception:
        log.warning("退出登录失败，忽略")
    finally:
        session.client.close()


@contextmanager
def _session(cfg: dict):
    """一次处置内复用同一个会话：进来登录、出去退登并关连接。"""
    session = _login(cfg)
    try:
        yield session
    finally:
        _logout(session)


def test_connection(cfg: dict) -> ProbeResult:
    session = _login(cfg)
    _logout(session)
    return ProbeResult(ok=True, message="登录成功")


def _matches(row: dict, ip: str) -> bool:
    """判断查询返回的一条记录是否就是这个 IP。

    静态黑名单 IP 条目看 `ipaddr`（`mark=ip`），五元组条目看 `sip`，地址段条目看 `ip_start`/`ip_end`。
    """
    if str(row.get("ipaddr") or "").strip() == ip:
        return True

    value = row.get("sip")
    singles = value if isinstance(value, list) else [value]
    for item in singles:
        if item and str(item) == ip:
            return True

    start = row.get("ip_start")
    end = row.get("ip_end")
    start = start[0] if isinstance(start, list) and start else start
    end = end[0] if isinstance(end, list) and end else end
    if not start or not end:
        return False
    try:
        target = ipaddress.ip_address(ip)
        return ipaddress.ip_address(str(start)) <= target <= ipaddress.ip_address(str(end))
    except ValueError:
        return False


def _query(session: _Session, path: str, commands: dict, action: str) -> dict:
    payload = _json_body(session.get(path, commands), action)
    if payload.get("result") is False:
        reason = payload.get("data")
        reason = reason if isinstance(reason, str) and reason else "设备未返回原因"
        raise DeviceError("vendor_rejected", f"{action}被设备拒绝：{reason}", retryable=False)
    return payload


def _query_rows(session: _Session, ip: str) -> list:
    """按 IP 查询静态黑名单；设备解析不了该地址（如 240/4 保留段）时退化为拉全量比对。"""
    commands = [{"pf_blacklist_static_search": {"detail": ip, "from": "1", "num": "20"}}]
    try:
        payload = _query(session, BLACKLIST_SEARCH, commands, "查询黑名单")
        return payload.get("rows") or []
    except DeviceError as exc:
        if exc.code != "vendor_rejected":
            raise
        log.warning("%s，改为拉取全部记录比对", exc)
    payload = _query(session, BLACKLIST_SHOW_ALL, {"0": {"pf_blacklist_show_all": ""}}, "查询全部黑名单")
    rows = payload.get("rows") or []
    log.info("全量查询返回 %s 条（total=%s）", len(rows), payload.get("total"))
    return rows


def _entries(session: _Session, ip: str) -> list:
    rows = [row for row in _query_rows(session, ip) if isinstance(row, dict)]
    return [row for row in rows if _matches(row, ip)]


def _expect_result(body: str, action: str) -> None:
    payload = _json_body(body, action)
    if payload.get("result") is not True:
        reason = payload.get("data")
        reason = reason if isinstance(reason, str) and reason else "设备未返回原因"
        raise DeviceError("vendor_rejected", f"{action}失败：{reason}", retryable=False)


def _group_name(session: _Session) -> str:
    """取设备上实际存在的策略组名：优先默认组，其次第一个组，查不到再用文档示例值。"""
    if session.group_name:
        return session.group_name
    names = []
    try:
        payload = _query(
            session,
            POLICY_GROUP,
            [{"blacklist_profile_group_show": {"from": "1", "num": "20"}}],
            "查询策略组",
        )
        names = [
            str(row.get("name") or "").strip()
            for row in (payload.get("rows") or [])
            if isinstance(row, dict) and str(row.get("name") or "").strip()
        ]
    except DeviceError as exc:
        log.warning("查询策略组失败，沿用 %s：%s", GROUP_NAME, exc)
    session.group_name = GROUP_NAME if GROUP_NAME in names or not names else names[0]
    log.info("使用策略组：%s（设备上的组：%s）", session.group_name, ", ".join(names) or "未知")
    return session.group_name


def _add_rule(ip: str, direction: str, group: str) -> dict:
    return {
        "blacklist_cfg_add_ip": {
            "ipaddr": ip,
            "enable": "yes",
            "direction": direction,
            "except_priv_ip": "off",
            "group_name": group,
            "comment": BLOCK_COMMENT,
        }
    }


def _add_direction(session: _Session, ip: str, direction: str, group: str) -> None:
    _expect_result(session.post(BLACKLIST_ADD, [_add_rule(ip, direction, group)]), "添加黑名单")


def block(ip: str, cfg: dict, ctx=None) -> None:
    """ctx 仅为签名兼容：平台按 block(ip, cfg) 调用，不会传值。"""
    target = check_ip(ip)
    with _session(cfg) as session:
        have = {str(row.get("direction") or "") for row in _entries(session, target)}
        if all(direction in have for direction in BLOCK_DIRECTIONS):
            log.info("IP 已按源、目的封禁，跳过：%s", target)
            return
        group = _group_name(session)
        if BLOCK_DIRECTIONS[0] not in have:
            try:
                _add_direction(session, target, BLOCK_DIRECTIONS[0], group)
            except DeviceError as exc:
                if not have:
                    raise
                # 设备只留一条记录时旧条目占着位置，删掉才有位置放源方向
                log.warning("源方向被拒（%s），已有方向 %s，删除后重建：%s", exc, "/".join(sorted(have)), target)
                body = session.post(BLACKLIST_DELETE, [{"blacklist_cfg_delete_ip": [{"ipaddr": target}]}])
                _expect_result(body, "删除黑名单")
                have.clear()
                _add_direction(session, target, BLOCK_DIRECTIONS[0], group)
        if BLOCK_DIRECTIONS[1] not in have:
            try:
                _add_direction(session, target, BLOCK_DIRECTIONS[1], group)
            except DeviceError as exc:
                log.warning("目的方向未下发（设备只允许一个方向时属正常）：%s（%s）", target, exc)


def unblock(ip: str, cfg: dict, ctx=None) -> None:
    """ctx 仅为签名兼容：平台按 unblock(ip, cfg) 调用，不会传值。"""
    target = check_ip(ip)
    with _session(cfg) as session:
        if not _entries(session, target):
            log.info("IP 不在黑名单，跳过：%s", target)
            return
        # 删除按 IP 下发，设备会一并清掉该地址的各方向条目
        body = session.post(BLACKLIST_DELETE, [{"blacklist_cfg_delete_ip": [{"ipaddr": target}]}])
        _expect_result(body, "删除黑名单")
