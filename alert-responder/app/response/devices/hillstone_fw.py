"""山石网科防火墙设备脚本（一个设备一个文件）。

封禁落点 = 地址簿（`/rest/api/addrbook`）：把 IP 以主机对象（`netmask` 32、`flag` 0）写进指定
地址簿组，**该组必须已被安全策略引用才会真正阻断**；地址簿本身只是对象容器。

认证约定（以 MCP 客户端实现为准，并兼容老固件）：

- Token：`POST /rest/api/login` body `{"api_token": "..."}`
- 用户名密码：`POST /rest/api/login` body `{"lang":"en","userName":"<base64>","password":"<base64>"}`
- 老固件若要求明文，退回 `{"userName":"明文","password":"明文","encodeUserName":"0","encodePassword":"0"}`
- 会话只用请求头传递：`X-Auth-Token`/`X-Auth-Role`/`X-Auth-VsysId`/`X-Auth-Fromrootvsys`/`X-Auth-Username`，
  另带 `X-API-Language`
- `401` 或 `error_code` 为 `loginError_1001/1002/1003` 时重登一次再重试

写地址簿后一律回读：设备写入返回码不稳定，**以组内是否真的出现/消失该 IP 作为成败判据**。
"""

import base64
import json

from sensemind_device import (
    DeviceError,
    ProbeResult,
    check_ip,
    http_client,
    logger,
    send,
    status_error,
)

MANIFEST = {
    "key": "hillstone_fw",
    "display_name": "山石网科防火墙",
    "schema_version": 1,
    "order": 5,
    "config_schema": [
        {
            "name": "base_url",
            "label": "管理地址",
            "type": "url",
            "required": True,
            "placeholder": "https://10.0.0.1:8443",
            "help": "含协议与 WebUI 端口（443 或 8443，按设备实际）",
        },
        {
            "name": "api_token",
            "label": "API Token",
            "type": "password",
            "required": False,
            "secret": True,
            "help": "有新版本 API Token 时填这里（优先使用）；留空则用下面的用户名密码",
        },
        {
            "name": "username",
            "label": "用户名",
            "type": "text",
            "required": False,
            "help": "与密码一起用；已填 API Token 时可留空",
        },
        {
            "name": "password",
            "label": "密码",
            "type": "password",
            "required": False,
            "secret": True,
            "help": "填明文，脚本按设备要求做 base64 编码",
        },
        {
            "name": "group_name",
            "label": "地址簿组名",
            "type": "text",
            "required": True,
            "default": "SenseMind-Block",
            "help": "封禁 IP 写入该地址簿组；该组需在安全策略中被引用后才会阻断流量",
        },
    ],
    "capabilities": {"ipv6": False},
}

log = logger("hillstone_fw")

LOGIN_PATH = "/rest/api/login"
ADDRBOOK_PATH = "/rest/api/addrbook"
DEFAULT_LOCALE = "en"
DEFAULT_GROUP = "SenseMind-Block"
MAX_ATTEMPTS = 2
QUERY_LIMIT = 200
SESSION_ERROR_CODES = {"loginError_1001", "loginError_1002", "loginError_1003"}
# 山石 WebUI 真实客户端的 Accept；部分固件只认 text/plain 的请求体，需兜底
ACCEPT_HEADER = "text/plain;charset=UTF-8, application/json;q=0.9, */*;q=0.8"
PLAIN_CONTENT_TYPE = "text/plain;charset=UTF-8"


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _group_name(cfg: dict) -> str:
    name = str(cfg.get("group_name") or DEFAULT_GROUP).strip()
    if not name:
        raise DeviceError("config_invalid", "缺少地址簿组名", retryable=False)
    return name


def _payload(response, action: str):
    try:
        return response.json()
    except ValueError:
        raise DeviceError(
            "bad_response", f"{action}失败：响应不是有效 JSON（HTTP {response.status_code}）"
        ) from None


def _items(payload) -> list:
    """地址簿响应可能是数组，也可能包在 result/data/items 里。"""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        result = payload.get("result")
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            for key in ("data", "items", "list"):
                value = result.get(key)
                if isinstance(value, list):
                    return value
            return [result]
        if isinstance(payload.get("data"), list):
            return payload["data"]
    return []


def _group_ips(group) -> list:
    """从组定义里递归取 ip_addr，去重保序。"""
    found = []

    def walk(node):
        if isinstance(node, dict):
            value = node.get("ip_addr")
            if isinstance(value, str) and value.strip():
                found.append(value.strip())
            for item in node.values():
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(group.get("ip") if isinstance(group, dict) else group)
    seen, ordered = set(), []
    for ip in found:
        if ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def _is_session_expired(response, payload) -> bool:
    # 401/403 都按会话失效处理（与设备侧「401、403 清会话」的行为一致）
    if response.status_code in (401, 403):
        return True
    if isinstance(payload, dict):
        if payload.get("error_code") in SESSION_ERROR_CODES:
            return True
        exception = payload.get("exception")
        if isinstance(exception, dict) and exception.get("code") in SESSION_ERROR_CODES:
            return True
    return False


class _FwClient:
    """一次操作内的会话封装：登录、带会话头请求、失效自动重登一次。"""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.locale = str(cfg.get("locale") or DEFAULT_LOCALE)
        self.http = None
        self.session: dict = {}
        self.mode = ""

    # ---------- 生命周期 ----------

    def close(self) -> None:
        if self.http is not None:
            self.http.close()
            self.http = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_exc):
        self.close()

    def open(self) -> None:
        self.close()
        self.session = {}
        self.http = http_client(self.cfg, headers=self._headers())
        self._login()

    # ---------- 认证 ----------

    def _headers(self) -> dict:
        headers = {
            "Accept": ACCEPT_HEADER,
            "Content-Type": "application/json",
            "X-API-Language": self.locale,
        }
        if self.session:
            headers.update(
                {
                    "X-Auth-Token": self.session["token"],
                    "X-Auth-Role": self.session["role"],
                    "X-Auth-VsysId": self.session["vsysId"],
                    "X-Auth-Fromrootvsys": self.session["fromrootvsys"],
                    "X-Auth-Username": self.session["username"],
                }
            )
        return headers

    def _login_bodies(self) -> list:
        token = str(self.cfg.get("api_token") or "").strip()
        if token:
            return [("token", {"api_token": token})]
        username = str(self.cfg.get("username") or "").strip()
        password = self.cfg.get("password") or ""
        if not username or not password:
            raise DeviceError(
                "config_invalid",
                "请填写 API Token，或填写用户名 + 密码",
                retryable=False,
            )
        return [
            (
                "base64",
                {
                    "lang": self.locale,
                    "userName": _b64(username),
                    "password": _b64(password),
                },
            ),
            (
                "plain",
                {
                    "lang": self.locale,
                    "userName": username,
                    "password": password,
                    "encodeUserName": "0",
                    "encodePassword": "0",
                },
            ),
        ]

    def _login(self) -> None:
        reasons = []
        for mode, body in self._login_bodies():
            response = send(self.http, "POST", LOGIN_PATH, json=body)
            if response.status_code >= 400:
                reasons.append(f"{mode}: HTTP {response.status_code}")
                continue
            payload = _payload(response, "登录")
            if isinstance(payload, dict) and payload.get("success") is False:
                reason = payload.get("message") or payload.get("error_code") or "设备拒绝"
                reasons.append(f"{mode}: {reason}")
                continue
            items = _items(payload)
            first = items[0] if items and isinstance(items[0], dict) else {}
            token = str(first.get("token") or "").strip()
            if not token:
                reasons.append(f"{mode}: 未返回 token")
                continue
            self.session = {
                "token": token,
                "role": str(first.get("role") or "admin"),
                "vsysId": str(first.get("vsysId") or "0"),
                "fromrootvsys": str(first.get("fromrootvsys") or "true"),
                "username": str(first.get("username") or self.cfg.get("username") or ""),
            }
            self.mode = mode
            self.http.headers.update(self._headers())
            log.info(
                "登录成功（%s）：user=%s vsysId=%s role=%s",
                mode,
                self.session["username"],
                self.session["vsysId"],
                self.session["role"],
            )
            return
        raise DeviceError("login_failed", "登录失败：" + "；".join(reasons), retryable=False)

    # ---------- 请求 ----------

    @staticmethod
    def _raise_vendor_error(payload, action: str) -> None:
        if not isinstance(payload, dict):
            return
        if payload.get("success") is False:
            reason = payload.get("message") or payload.get("error") or "设备拒绝"
            raise DeviceError("vendor_rejected", f"{action}失败：{reason}", retryable=False)
        error_code = payload.get("error_code")
        if error_code not in (None, "", 0, "0"):
            raise DeviceError(
                "vendor_rejected", f"{action}失败：{payload.get('message') or error_code}", retryable=False
            )

    def _send_once(self, method: str, path: str, *, params=None, json=None, action: str):
        """返回 (payload, expired)。expired=True 表示会话失效，交由调用方重登重试。"""
        response = send(self.http, method, path, params=params, json=json)
        if json is not None and response.status_code in (400, 415):
            # 个别固件只接受 text/plain 承载 JSON，重试一次
            log.warning("%s 返回 HTTP %s，改用 text/plain 重试一次", action, response.status_code)
            response = send(
                self.http,
                method,
                path,
                params=params,
                json=json,
                headers={"Content-Type": PLAIN_CONTENT_TYPE},
            )
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if _is_session_expired(response, payload):
            return None, True
        if response.status_code >= 400:
            raise status_error(response, message=f"{action}请求被拒绝")
        if payload is None:
            raise DeviceError(
                "bad_response", f"{action}失败：响应不是有效 JSON（HTTP {response.status_code}）"
            )
        self._raise_vendor_error(payload, action)
        return payload, False

    def call(self, method: str, path: str, *, params=None, json=None, action: str):
        payload, expired = self._send_once(method, path, params=params, json=json, action=action)
        if not expired:
            return payload
        log.warning("会话已失效，重新登录后重试：%s", action)
        self._login()
        payload, expired = self._send_once(method, path, params=params, json=json, action=action)
        if expired:
            raise DeviceError(
                "session_expired",
                f"{action}失败：重新登录后仍被拒绝（持续出现请检查账号是否有该接口/地址簿权限）",
                retryable=True,
            )
        return payload

    # ---------- 地址簿 ----------

    def read_group(self, name: str):
        query = {
            "conditions": [{"field": "name", "value": name}],
            "start": 0,
            "limit": QUERY_LIMIT,
            "page": 1,
        }
        payload = self.call(
            "GET",
            ADDRBOOK_PATH,
            params={"query": json.dumps(query, ensure_ascii=False)},
            action="查询地址簿",
        )
        for item in _items(payload):
            if isinstance(item, dict) and str(item.get("name") or "") == name:
                return item
        return None

    def write_group(self, name: str, ips: list, *, create: bool) -> None:
        body = [
            {
                "name": name,
                "ip": [{"ip_addr": ip, "netmask": "32", "flag": 0} for ip in ips],
            }
        ]
        self.call(
            "POST" if create else "PUT",
            ADDRBOOK_PATH,
            json=body,
            action="新建地址簿组" if create else "覆盖地址簿组",
        )


def test_connection(cfg: dict) -> ProbeResult:
    name = _group_name(cfg)
    with _FwClient(cfg) as client:
        group = client.read_group(name)
    if group is None:
        return ProbeResult(ok=True, message=f"登录成功；地址簿组 {name} 尚不存在，首次封禁会创建")
    return ProbeResult(ok=True, message=f"登录成功；地址簿组 {name} 现有 {len(_group_ips(group))} 个 IP")


def block(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    name = _group_name(cfg)
    with _FwClient(cfg) as client:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            group = client.read_group(name)
            ips = _group_ips(group) if group is not None else []
            if target in ips:
                log.info("IP 已在地址簿组 %s，跳过：%s", name, target)
                return
            client.write_group(name, ips + [target], create=group is None)
            current = client.read_group(name)
            if current is not None and target in _group_ips(current):
                if attempt > 1:
                    log.warning("第 %s 次写入后确认生效：%s", attempt, target)
                log.info("已加入地址簿组 %s：%s", name, target)
                return
            log.warning("写入后回读未见 %s（第 %s 次），重试", target, attempt)
    raise DeviceError(
        "block_not_effective",
        f"设备返回成功但地址簿组 {name} 内未见 {target}",
        retryable=True,
    )


def unblock(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    name = _group_name(cfg)
    with _FwClient(cfg) as client:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            group = client.read_group(name)
            ips = _group_ips(group) if group is not None else []
            if target not in ips:
                log.info("IP 不在地址簿组 %s，跳过：%s", name, target)
                return
            client.write_group(name, [item for item in ips if item != target], create=False)
            current = client.read_group(name)
            if current is None or target not in _group_ips(current):
                log.info("已移出地址簿组 %s：%s", name, target)
                return
            log.warning("删除后回读仍有 %s（第 %s 次），重试", target, attempt)
    raise DeviceError(
        "unblock_not_effective",
        f"设备返回成功但地址簿组 {name} 内仍有 {target}",
        retryable=True,
    )


def list_blocked(cfg: dict) -> list:
    name = _group_name(cfg)
    with _FwClient(cfg) as client:
        group = client.read_group(name)
    ips = _group_ips(group) if group is not None else []
    log.info("地址簿组 %s 共 %s 条", name, len(ips))
    return sorted(ips)
