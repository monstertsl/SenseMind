"""天融信防火墙设备脚本（一个设备一个文件）。

实现依据：`docs/topsec_firewall/下一代防火墙webui管理接口说明文档_V37.6`（官方接口文档）。

调用约定（文档「注意事项 → 统一参数获取」）：

- 登录 `POST /home/login/addNoCode/`：`name` + `password` + `pwdlen`；密码用 AES-CBC
  （密钥/偏移量均为 `ngfwrestapilogin`、零填充、输出 base64），`pwdlen` 是明文长度。
  响应正文是 base64 JSON，`data.authid` 即 userMark，`data.secret` 参与 codeRun。
- 除登录外每个接口都必须带登录返回的 Cookie、`Referer` 与 `Content-Type` 表头。
- `token`：响应里 `?[` 与 `}?` 之间的字符串，每次请求都会换新的，下一次请求必须用最新的。
- `codeRun` = `md5(secret + token + url + commands 的 JSON)`。
- 黑名单落点：`资源管理 → 黑名单传播`（`blackListSpread`），按五元组下发与删除。
"""

import base64
import hashlib
import ipaddress
import json
from contextlib import contextmanager

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
BLACKLIST_ADD = "/home/default/blackListSpread/add/"
BLACKLIST_DELETE = "/home/default/blackListSpread/deleteLots/"
BLACKLIST_SEARCH = "/home/default/blackListSpread/searchpf/"

# 设备登录表单的口令加密参数（官方文档固定值）
LOGIN_AES_KEY = "ngfwrestapilogin"
LOGIN_AES_IV = "ngfwrestapilogin"


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


def _code_run(secret: str, token: str, url: str, commands: dict) -> str:
    serialized = json.dumps(commands, ensure_ascii=False, separators=(",", ":"))
    return hashlib.md5((secret + token + url + serialized).encode("utf-8")).hexdigest()


class _Session:
    """持有 cookie / userMark / secret / token 的会话，token 每次响应轮转。"""

    def __init__(self, client, token: str, user_mark: str, secret: str):
        self.client = client
        self.token = token
        self.user_mark = user_mark
        self.secret = secret

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
        fields: dict = {}
        _flatten("commands", commands, fields)
        if self.token:
            fields["token"] = self.token
        if self.secret:
            fields["codeRun"] = _code_run(self.secret, self.token, path, commands)
        response = send(
            self.client,
            "POST",
            path,
            params={"userMark": self.user_mark},
            data=fields,
            headers=self._headers(),
        )
        return self._absorb(response)

    def get(self, path: str, commands: dict | None = None) -> str:
        params: dict = {"userMark": self.user_mark}
        if commands:
            _flatten("commands", commands, params)
        if self.token:
            params["token"] = self.token
        if commands and self.secret:
            params["codeRun"] = _code_run(self.secret, self.token, path, commands)
        response = send(self.client, "GET", path, params=params, headers=self._headers())
        return self._absorb(response)


def _login(cfg: dict) -> _Session:
    client = http_client(cfg)
    try:
        password = str(cfg.get("password") or "")
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
        payload = _decode_login_body(body)
        data = payload.get("data")
        if payload.get("result") is not True:
            reason = data if isinstance(data, str) else "设备拒绝登录"
            raise DeviceError("login_failed", f"登录失败：{reason}", retryable=False)
        data = data if isinstance(data, dict) else {}
        user_mark = str(data.get("authid") or "").strip()
        if not user_mark:
            raise DeviceError("login_failed", "登录响应未返回 authid", retryable=False)
        secret = str(data.get("secret") or "").strip()
    except BaseException:
        client.close()
        raise
    return _Session(client, token, user_mark, secret)


def _logout(session: _Session) -> None:
    try:
        send(
            session.client,
            "GET",
            LOGOUT_PATH,
            params={"userMark": session.user_mark, "token": session.token},
            headers=session._headers(),
        )
    except Exception:
        log.warning("退出登录失败，忽略")
    finally:
        session.client.close()


@contextmanager
def _session(cfg: dict, ctx):
    if ctx and ctx.get("session") is not None:
        yield ctx["session"]
        return
    session = _login(cfg)
    try:
        yield session
    finally:
        _logout(session)


def setup(cfg: dict) -> dict:
    return {"session": _login(cfg)}


def teardown(ctx) -> None:
    if ctx and ctx.get("session") is not None:
        _logout(ctx["session"])


def test_connection(cfg: dict) -> ProbeResult:
    session = _login(cfg)
    _logout(session)
    return ProbeResult(ok=True, message="登录成功")


def _matches(row: dict, ip: str) -> bool:
    """判断搜索返回的一条记录是否就是这个 IP（sip 为五元组形式，ip_start/ip_end 为地址段形式）。"""
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


def _entries(session: _Session, ip: str) -> list:
    body = session.get(BLACKLIST_SEARCH, {"0": {"pf_blacklist_static_search": {"0": ip}}})
    payload = _json_body(body, "查询黑名单")
    if payload.get("result") is False:
        raise DeviceError("vendor_rejected", "查询黑名单被设备拒绝", retryable=False)
    rows = payload.get("rows")
    rows = rows if isinstance(rows, list) else []
    return [row for row in rows if isinstance(row, dict) and _matches(row, ip)]


def _expect_result(body: str, action: str) -> None:
    payload = _json_body(body, action)
    if payload.get("result") is not True:
        reason = payload.get("data")
        reason = reason if isinstance(reason, str) and reason else "设备未返回原因"
        raise DeviceError("vendor_rejected", f"{action}失败：{reason}", retryable=False)


def block(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    with _session(cfg, ctx) as session:
        if _entries(session, target):
            log.info("IP 已在黑名单，跳过：%s", target)
            return
        body = session.post(
            BLACKLIST_ADD,
            {
                "0": {
                    "pf_blacklist_add": {
                        "sip": target,
                        "sport": "",
                        "dip": "",
                        "dport": "",
                        "l4_protocol": "",
                    }
                }
            },
        )
        _expect_result(body, "添加黑名单")


def unblock(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    with _session(cfg, ctx) as session:
        if not _entries(session, target):
            log.info("IP 不在黑名单，跳过：%s", target)
            return
        body = session.post(
            BLACKLIST_DELETE,
            {
                "0": {
                    "pf_blacklist_delete": {
                        "0": {
                            "sip": target,
                            "sport": "",
                            "dip": "",
                            "dport": "",
                            "l4_protocol": "",
                        }
                    }
                }
            },
        )
        _expect_result(body, "删除黑名单")
