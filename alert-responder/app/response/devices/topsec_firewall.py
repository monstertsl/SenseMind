"""天融信防火墙设备脚本（一个设备一个文件）。

调用约定：

- 登录有两个接口：优先 `POST /home/restLogin/`，该接口不存在（HTTP 404）时回落到
  `POST /home/login/addNoCode/`。
  - `restLogin`：表单 `name` + `password` + `ngtosAuth`，两者都用 AES-CBC 加密（密钥/偏移量均为
    16 个 `1`、零填充、输出 base64），`ngtosAuth` 是加密后的明文长度；token 由响应的 `tokens`
    数组给出而非响应前缀。
  - `addNoCode`（老固件）：`name` + `password` + `pwdlen`，密码用 AES-CBC 但密钥/偏移量换成
    `ngfwrestapilogin`，`pwdlen` 是明文长度；响应正文是 base64 JSON，`data.authid` 即 userMark，
    `data.secret` 参与 codeRun。
- 建议在设备上关掉登录验证码：不同版本固件的验证码机制不一样，开着可能挡住其中一个接口。
- 除登录外每个接口都必须带登录返回的 Cookie、`Referer` 与 `Content-Type` 表头。
- `token`：响应里 `?[` 与 `}?` 之间的字符串，每次请求都会换新的，下一次请求必须用最新的。
- `codeRun` = `md5(secret + token + url + commands 的 JSON)`，JSON 按设备侧的数组形态
  （`[{"pf_blacklist_add":{"sip":"1.1.1.1"}}]`）序列化，不能带数字键。
- 参数键保留字面量：`commands[0][pf_blacklist_add][sip]` 里的 `[` `]` 不能百分号编码，
  否则设备解析不出命令，返回「无效输入，分析错误」。
- 黑名单落点：「安全策略 → 黑白名单 → 静态黑名单」。可用的 HTTP 接口有两套，由 `_use_static()` 探测后二选一：
  - 接口 A `blackWhite`（3.7 起提供）：`whiteIpAdd` 添加（`ipaddr` + `direction`，策略组名只能用策略组
    接口返回的），`addrStaticBlackSearch` 按 IP 查，删除用 `blacklist_cfg_delete_ip`。
  - 接口 B `blackListSpread`（老固件只有这套）：`add` 下五元组 `sip`/`dip`，`showAll` 拉全量本地比对，
    删除按条目原值下发 `pf_blacklist_delete`（五个维度都要带，不限的传空串）。
- 探测看「查策略组」：该接口报 `cfg文件不存在` 说明 `blackWhite` 这套接口在设备上不可用，添加也必然失败。
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
    # 未实现 list_blocked：设备返回的是五元组条目，与平台「已封禁 IP 列表」的语义不对应
    "capabilities": {"ipv6": False},
}

log = logger("topsec_firewall")

LOGIN_PATH = "/home/login/addNoCode/"
LOGOUT_PATH = "/home/index/logout/"
RESTLOGOUT_PATH = "/home/restLogout/"
# 落点：安全策略 → 黑白名单 → 静态黑名单。能操作这份名单的 HTTP 接口有两套，按设备能力二选一
# （详见 _use_static）：
#   static = blackWhite，新固件，条目 mark=ip、带 ipaddr + direction
#   spread = blackListSpread，老固件，条目 mark=tuple、是五元组 sip/dip
STATIC_SEARCH = "/home/default/blackWhite/addrStaticBlackSearch/"
STATIC_ADD = "/home/default/blackWhite/whiteIpAdd/"
STATIC_POLICY_GROUP = "/home/default/blackWhite/showPolicyGroup/"
SPREAD_ADD = "/home/default/blackListSpread/add/"
SPREAD_SHOW_ALL = "/home/default/blackListSpread/showAll/"
# 两套落点共用同一个删除入口，靠命令名区分：静态黑名单 blacklist_cfg_delete_ip、五元组 pf_blacklist_delete
BLACKLIST_DELETE = "/home/default/blackListSpread/deleteLots/"
# 源方向必须封住（只有它拦得住攻击源主动发来的流量）；目的方向尽力下发，被拒只记日志
BLOCK_DIRECTIONS = ("src", "dst")
# 五元组里方向对应的维度
DIRECTION_FIELDS = {"src": "sip", "dst": "dip"}
# 五元组删除要原样带回的维度，空数组表示该维度不限，下发空串
TUPLE_FIELDS = ("sip", "sport", "dip", "dport", "l4_protocol")
# 静态黑名单的策略组：只能用设备列表里实际存在的名字，查不到就不传
DEFAULT_GROUP = "default_group"
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
        self.mode = ""  # ""=还没探测；"static"=静态黑名单；"spread"=黑名单传播五元组
        self.group = ""  # 静态黑名单的策略组，空串表示不传

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


def _value(row: dict, key: str) -> str:
    """取条目里某个维度的值：单值字段是字符串，多值字段是数组（空数组表示该维度不限）。"""
    value = row.get(key)
    if isinstance(value, list):
        return str(value[0]).strip() if value else ""
    return "" if value is None else str(value).strip()


def _holds(row: dict, key: str, ip: str) -> bool:
    """条目的某个维度里是否包含这个 IP（多值字段逐个比）。"""
    value = row.get(key)
    items = value if isinstance(value, list) else [value]
    return any(item and str(item).strip() == ip for item in items)


def _range_covers(row: dict, ip: str) -> bool:
    start = _value(row, "ip_start")
    end = _value(row, "ip_end")
    if not start or not end:
        return False
    try:
        target = ipaddress.ip_address(ip)
        return ipaddress.ip_address(start) <= target <= ipaddress.ip_address(end)
    except ValueError:
        return False


def _matches(row: dict, ip: str) -> bool:
    """条目是否命中该 IP：静态黑名单看 ipaddr，五元组看 sip/dip，地址段看 ip_start/ip_end。"""
    return (
        _holds(row, "ipaddr", ip)
        or _holds(row, "sip", ip)
        or _holds(row, "dip", ip)
        or _range_covers(row, ip)
    )


def _query(session: _Session, path: str, commands: dict, action: str) -> dict:
    payload = _json_body(session.get(path, commands), action)
    if payload.get("result") is False:
        reason = payload.get("data")
        reason = reason if isinstance(reason, str) and reason else "设备未返回原因"
        raise DeviceError("vendor_rejected", f"{action}被设备拒绝：{reason}", retryable=False)
    return payload


def _expect_result(body: str, action: str) -> None:
    payload = _json_body(body, action)
    if payload.get("result") is not True:
        reason = payload.get("data")
        reason = reason if isinstance(reason, str) and reason else "设备未返回原因"
        raise DeviceError("vendor_rejected", f"{action}失败：{reason}", retryable=False)


def _use_static(session: _Session) -> bool:
    """探测该设备能用的落点，返回 True 表示走静态黑名单，False 表示走黑名单传播五元组。

    探针用「查策略组」而不是「添加」：3.7 的静态黑名单同一 IP 只允许一条记录，添加被拒
    不等于模块不可用；而策略组接口报「cfg文件不存在」就说明这套配置在设备上根本不存在，
    此时 whiteIpAdd 无论带不带 group_name 都加不进去（真机实测）。
    """
    if session.mode:
        return session.mode == "static"
    try:
        payload = _query(
            session,
            STATIC_POLICY_GROUP,
            [{"blacklist_profile_group_show": {"from": "1", "num": "20"}}],
            "查询策略组",
        )
    except DeviceError as exc:
        log.warning("静态黑名单接口 blackWhite 不可用（%s），改用黑名单传播接口 blackListSpread", exc)
        session.mode = "spread"
        return False
    names = [
        str(row.get("name") or "").strip()
        for row in (payload.get("rows") or [])
        if isinstance(row, dict) and str(row.get("name") or "").strip()
    ]
    if DEFAULT_GROUP in names:
        session.group = DEFAULT_GROUP
    else:
        session.group = names[0] if names else ""
    session.mode = "static"
    log.info("使用静态黑名单接口 blackWhite（策略组：%s）", session.group or "不传")
    return True


def _entries(session: _Session, ip: str) -> list:
    """该 IP 命中的全部条目。

    静态黑名单先按 IP 精确搜（`detail`），设备解析不了该输入时退化为 `showAll` 拉全量本地比对；
    五元组没有可按 IP 搜的可用接口，直接 `showAll` 全量比对。
    """
    if _use_static(session):
        try:
            payload = _query(
                session,
                STATIC_SEARCH,
                [{"pf_blacklist_static_search": {"detail": ip, "from": "1", "num": "20"}}],
                "查询黑名单",
            )
            rows = [row for row in (payload.get("rows") or []) if isinstance(row, dict)]
            hits = [row for row in rows if _matches(row, ip)]
            log.info("静态黑名单返回 %s 条，命中 %s 条", len(rows), len(hits))
            return hits
        except DeviceError as exc:
            log.warning("%s，改为拉取全部记录比对", exc)
    payload = _query(session, SPREAD_SHOW_ALL, {"0": {"pf_blacklist_show_all": ""}}, "查询全部黑名单")
    rows = [row for row in (payload.get("rows") or []) if isinstance(row, dict)]
    hits = [row for row in rows if _matches(row, ip)]
    log.info("黑名单共 %s 条（total=%s），命中该地址 %s 条", len(rows), payload.get("total"), len(hits))
    return hits


def _covered(entries: list, ip: str) -> set:
    """已封住的方向。

    静态黑名单条目自带 `direction`；五元组条目没有方向字段，`sip=<ip>` 即源方向、`dip=<ip>` 即目的方向。
    地址段条目两个方向都算封住。
    """
    have = set()
    for row in entries:
        if _range_covers(row, ip):
            have.update(BLOCK_DIRECTIONS)
            continue
        direction = str(row.get("direction") or "").strip()
        if direction in BLOCK_DIRECTIONS:
            have.add(direction)
            continue
        if _holds(row, "sip", ip):
            have.add("src")
        if _holds(row, "dip", ip):
            have.add("dst")
    return have


def _add_static(session: _Session, ip: str, direction: str) -> None:
    rule = {
        "ipaddr": ip,
        "enable": "yes",
        "direction": direction,
        "except_priv_ip": "off",
        "comment": BLOCK_COMMENT,
    }
    if session.group:
        rule["group_name"] = session.group
    _expect_result(session.post(STATIC_ADD, [{"blacklist_cfg_add_ip": rule}]), "添加黑名单")


def _add_tuple(session: _Session, ip: str, direction: str) -> None:
    _expect_result(
        session.post(SPREAD_ADD, [{"pf_blacklist_add": {DIRECTION_FIELDS[direction]: ip}}]),
        "添加黑名单",
    )


def _delete_entry(session: _Session, row: dict) -> None:
    """按条目形态选删除命令：静态黑名单按 ipaddr 删，五元组按条目原值删。"""
    if _value(row, "ip_start"):
        log.warning("地址段条目不支持按 IP 删除，需在设备上处理")
        return
    ipaddr = _value(row, "ipaddr")
    if ipaddr:
        log.info("删除静态黑名单条目：ipaddr=%s", ipaddr)
        _expect_result(
            session.post(BLACKLIST_DELETE, [{"blacklist_cfg_delete_ip": [{"ipaddr": ipaddr}]}]),
            "删除黑名单",
        )
        return
    tuple_ = {field: _value(row, field) for field in TUPLE_FIELDS}
    log.info("删除五元组条目：%s", " ".join(f"{key}={value or '不限'}" for key, value in tuple_.items()))
    _expect_result(session.post(BLACKLIST_DELETE, [{"pf_blacklist_delete": [tuple_]}]), "删除黑名单")


def _block_static(session: _Session, target: str, entries: list, have: set) -> None:
    if "src" not in have:
        try:
            _add_static(session, target, "src")
        except DeviceError as exc:
            if not have:
                raise
            # 3.7 同一 IP 只允许一条记录，旧条目占着位置，删掉才有位置放源方向
            log.warning("源方向被拒（%s），已有方向 %s，删除后重建：%s", exc, "/".join(sorted(have)), target)
            for row in entries:
                _delete_entry(session, row)
            have.clear()
            _add_static(session, target, "src")
        log.info("源方向封禁成功：%s", target)
    if "dst" not in have:
        try:
            _add_static(session, target, "dst")
            log.info("目的方向封禁成功：%s", target)
        except DeviceError as exc:
            log.warning("目的方向未下发（设备只允许一个方向时属正常）：%s（%s）", target, exc)


def _block_tuple(session: _Session, target: str, have: set) -> None:
    for direction in BLOCK_DIRECTIONS:
        if direction in have:
            log.info("%s 方向已封禁，跳过：%s", direction, target)
            continue
        try:
            _add_tuple(session, target, direction)
            log.info("%s 方向封禁成功：%s（%s=%s）", direction, target, DIRECTION_FIELDS[direction], target)
        except DeviceError as exc:
            # 源方向封不住等于没封，抛给平台记失败；目的方向只匹配「发往该 IP」的报文，尽力即可
            if direction == BLOCK_DIRECTIONS[0]:
                raise
            log.warning("目的方向未下发（设备不允许该五元组时属正常）：%s（%s）", target, exc)


def block(ip: str, cfg: dict, ctx=None) -> None:
    """ctx 仅为签名兼容：平台按 block(ip, cfg) 调用，不会传值。"""
    target = check_ip(ip)
    with _session(cfg) as session:
        entries = _entries(session, target)
        have = _covered(entries, target)
        if all(direction in have for direction in BLOCK_DIRECTIONS):
            log.info("IP 已按源、目的封禁，跳过：%s", target)
            return
        if _use_static(session):
            _block_static(session, target, entries, have)
        else:
            _block_tuple(session, target, have)


def unblock(ip: str, cfg: dict, ctx=None) -> None:
    """ctx 仅为签名兼容：平台按 unblock(ip, cfg) 调用，不会传值。"""
    target = check_ip(ip)
    with _session(cfg) as session:
        entries = _entries(session, target)
        if not entries:
            log.info("IP 不在黑名单，跳过：%s", target)
            return
        for row in entries:
            _delete_entry(session, row)
