"""设备脚本自检：用 MockTransport 跑通 registry + ABI 全链路，无需真实设备。

运行：python -m app.response.selftest
"""

import base64
import json
import os
import sys
from urllib.parse import parse_qs

import httpx

import sensemind_device
from sensemind_device import DeviceError

from . import registry


class FakeSangfor:
    prefix = "/api/v1/namespaces/@namespace"

    def __init__(self) -> None:
        self.blocked = set()
        self.calls = []
        self.login_fails = False
        self.network_down = False
        self.ignore_block = False  # 模拟“设备返回成功但没真正写入”
        self.ignore_unblock = False  # 模拟“设备返回成功但没真正删除”

    def handle(self, request: httpx.Request):
        if self.network_down:
            raise httpx.ConnectError("mock network down", request=request)
        path = request.url.path
        self.calls.append((request.method, path))
        if path == f"{self.prefix}/login":
            if self.login_fails:
                return httpx.Response(200, json={"code": 1, "message": "用户名或密码错误"})
            return httpx.Response(
                200,
                json={"code": 0, "message": "成功", "data": {"loginResult": {"token": "sf-token"}}},
            )
        if path == f"{self.prefix}/logout":
            return httpx.Response(200, json={"code": 0, "message": "成功"})
        if path.startswith(f"{self.prefix}/whiteblacklist/"):
            ip = path.rsplit("/", 1)[-1]
            if request.method == "GET":
                if ip in self.blocked:
                    return httpx.Response(
                        200,
                        json={
                            "code": 0,
                            "message": "成功",
                            "data": {"enable": True, "type": "BLACK", "urlType": "ip", "url": ip},
                        },
                    )
                return httpx.Response(200, json={"code": 1, "message": "黑名单不存在"})
            if request.method == "DELETE":
                if not self.ignore_unblock:
                    self.blocked.discard(ip)
                return httpx.Response(200, json={"code": 0, "message": "成功"})
        if path == f"{self.prefix}/whiteblacklist":
            if request.method == "POST":
                if not self.ignore_block:
                    self.blocked.add(json.loads(request.content)["url"])
                return httpx.Response(200, json={"code": 0, "message": "成功"})
            if request.method == "GET":
                items = [
                    {"enable": True, "type": "BLACK", "urlType": "ip", "url": ip}
                    for ip in sorted(self.blocked)
                ]
                return httpx.Response(
                    200,
                    json={"code": 0, "message": "成功", "data": {"items": items, "totalPages": 1}},
                )
        return httpx.Response(404, json={"code": 404, "message": "not found"})


class FakeQianxin:
    def __init__(self) -> None:
        self.blocked = set()
        self.calls = []

    def handle(self, request: httpx.Request):
        path = request.url.path
        self.calls.append((request.method, path))
        ok = {"head": {"error_code": 0}, "body": {}}
        if path == "/v1.0/login/":
            return httpx.Response(
                200,
                json={"head": {"error_code": 0}, "result": {"token": "qx-token"}},
                headers={"set-cookie": "__s_sessionid__=sess-1; Path=/"},
            )
        if path == "/v1.0/out/":
            return httpx.Response(200, json=ok)
        if path == "/v1.0/rest/":
            item = json.loads(request.content)[0]
            function = item["head"]["function"]
            body = item.get("body", {})
            if function == "get_blacklist_config":
                key = body["addr_blacklist_cp"]["search_key"]
                hits = [ip for ip in self.blocked if ip == key]
                return httpx.Response(
                    200,
                    json={
                        "head": {"error_code": 0, "total": len(hits)},
                        "data": [{"ip_start": ip, "ip_end": ip} for ip in hits],
                    },
                )
            if function in ("add_blacklist_ip_web", "del_blacklist_by_id"):
                entry = body["addr_blacklist_cp"]["blacklist_cp"][0]
                ip = entry.get("ip_start")
                if function == "add_blacklist_ip_web":
                    self.blocked.add(ip)
                else:
                    self.blocked.discard(ip)
                return httpx.Response(200, json=ok)
        return httpx.Response(404, json=ok)


class FakeTopsec:
    """天融信 WebUI 表单接口：响应带 `?[token}?` 前缀且 token 轮转，非登录接口必须带 cookie 与 codeRun。"""

    def __init__(self) -> None:
        self.blocked = set()
        self.calls = []
        self.counter = 0
        self.login_fails = False
        self.login_form = {}
        self.missing_cookie = 0
        self.missing_code_run = 0
        self.stale_token = 0
        self.last_token = ""

    def _wrap(self, body: str) -> str:
        self.counter += 1
        self.last_token = f"tp-{self.counter}"
        return "?[" + self.last_token + "}?" + body

    def handle(self, request: httpx.Request):
        path = request.url.path
        self.calls.append((request.method, path))
        form = {}
        if request.method == "POST" and request.content:
            form = {key: values[0] for key, values in parse_qs(request.content.decode()).items()}

        if path == "/home/login/addNoCode/":
            self.login_form = form
            if self.login_fails:
                payload = base64.b64encode(
                    json.dumps({"result": False, "data": "用户名或密码错误"}).encode()
                ).decode()
                return httpx.Response(200, text=payload)
            payload = base64.b64encode(
                json.dumps(
                    {"result": True, "data": {"url": "home", "vsid": 0, "authid": "um-1", "secret": "sec-1"}}
                ).encode()
            ).decode()
            return httpx.Response(
                200,
                text=self._wrap(payload),
                headers={"set-cookie": "PHPSESSID=sess-1; Path=/"},
            )

        # 除登录外：必须带 cookie、codeRun，且 token 必须是上一次响应给的最新值
        if not request.headers.get("cookie"):
            self.missing_cookie += 1
        params = request.url.params
        if "codeRun" not in params and "codeRun" not in form:
            self.missing_code_run += 1
        sent_token = params.get("token") or form.get("token") or ""
        if self.last_token and sent_token != self.last_token:
            self.stale_token += 1

        if path == "/home/index/logout/":
            return httpx.Response(200, text=self._wrap('{"result":true,"data":"success"}'))
        if path == "/home/default/blackListSpread/searchpf/":
            ip = params.get("commands[0][pf_blacklist_static_search][0]")
            rows = [{"sip": ip, "mark": "tuple"}] if ip in self.blocked else []
            return httpx.Response(
                200,
                text=self._wrap(json.dumps({"rows": rows, "total": len(rows), "result": True})),
            )
        if path == "/home/default/blackListSpread/add/":
            self.blocked.add(form.get("commands[0][pf_blacklist_add][sip]"))
            return httpx.Response(200, text=self._wrap('{"result":true,"data":[]}'))
        if path == "/home/default/blackListSpread/deleteLots/":
            self.blocked.discard(form.get("commands[0][pf_blacklist_delete][0][sip]"))
            return httpx.Response(200, text=self._wrap('{"result":true,"data":[]}'))
        return httpx.Response(404, text="not found")


class FakeNsfocus:
    """绿盟 NF：静态 Token 认证 + 黑名单 info/configuration/delete 三段式。"""

    prefix = "/north/nf/strategy/globalWb/blist"

    def __init__(self) -> None:
        self.entries = {}
        self.next_id = 10001
        self.calls = []
        self.delete_bodies = []
        self.network_down = False
        self.ignore_block = False
        self.ignore_unblock = False
        self.truncate_search = False  # 模拟 search 只回部分结果、精确项不在首页

    def handle(self, request: httpx.Request):
        if self.network_down:
            raise httpx.ConnectError("mock network down", request=request)
        if request.headers.get("authorization") != "gl-token":
            return httpx.Response(401, json={"status": 401, "message": "Unauthorized"})
        path = request.url.path
        self.calls.append((request.method, path))

        if path == f"{self.prefix}/info/":
            search = request.url.params.get("search")
            if search and self.truncate_search:
                return httpx.Response(
                    200, json={"status": 2000, "result": {"total": len(self.entries), "list": []}}
                )
            rows = [
                {"id": entry_id, "ip": ip, "type": "sourceIp", "protocol": "any", "status": True}
                for entry_id, ip in self.entries.items()
            ]
            if search:
                rows = [row for row in rows if search in row["ip"]]
            return httpx.Response(
                200,
                json={"status": 2000, "module": "NF", "message": "获取成功", "result": {"total": len(rows), "list": rows}},
            )

        if path == f"{self.prefix}/configuration/":
            body = json.loads(request.content)
            if body.get("action") != "create":
                return httpx.Response(200, json={"status": 8204, "message": "范围不合规: action参数值有误"})
            created = self.next_id
            if not self.ignore_block:
                self.entries[created] = body.get("ip")
            self.next_id += 1
            return httpx.Response(200, json={"status": 2000, "message": "新建黑名单成功", "result": [created]})

        if path == f"{self.prefix}/delete/":
            body = json.loads(request.content)
            self.delete_bodies.append(body)
            if not self.ignore_unblock:
                for entry_id in body.get("id") or []:
                    self.entries.pop(int(entry_id), None)
            return httpx.Response(200, json={"status": "2000", "message": "删除成功", "result": {}})

        return httpx.Response(404, json={"status": 404, "message": "not found"})


class FakeHillstone:
    """山石网科：登录换会话（X-Auth-* + Cookie），封禁落点 = 地址簿组（POST 建组 / PUT 覆盖）。"""

    def __init__(self) -> None:
        self.groups = {}
        self.calls = []
        self.network_down = False
        self.login_fails = False
        self.reject_plain = True  # 老固件才接受明文，默认只认 base64
        self.reject_base64 = False
        self.ignore_block = False
        self.ignore_unblock = False
        self.missing_auth = 0
        self.logins = 0
        self.login_modes = []
        self.locale_seen = set()
        self.expire_once = False
        self.forbidden_once = False
        self.require_plain = False  # 个别固件只收 text/plain 承载的 JSON

    def handle(self, request: httpx.Request):
        if self.network_down:
            raise httpx.ConnectError("mock network down", request=request)
        path = request.url.path
        self.calls.append((request.method, path))

        if path == "/rest/api/login" and request.method == "POST":
            body = json.loads(request.content)
            self.logins += 1
            if self.login_fails:
                return httpx.Response(200, json={"success": False, "message": "用户名或密码错误"})
            if "api_token" in body:
                if body["api_token"] != "hs-api-token":
                    return httpx.Response(200, json={"success": False, "message": "token 无效"})
                self.login_modes.append("token")
                user = "token-admin"
            elif body.get("encodeUserName") == "0":
                if self.reject_plain:
                    return httpx.Response(200, json={"success": False, "message": "口令编码方式不支持"})
                self.login_modes.append("plain")
                user = body.get("userName")
                if body.get("password") != "secret":
                    return httpx.Response(200, json={"success": False, "message": "用户名或密码错误"})
            else:
                self.login_modes.append("base64")
                if self.reject_base64:
                    return httpx.Response(200, json={"success": False, "message": "userName 需明文"})
                user = base64.b64decode(body.get("userName") or "").decode("utf-8")
                if base64.b64decode(body.get("password") or "").decode("utf-8") != "secret":
                    return httpx.Response(200, json={"success": False, "message": "用户名或密码错误"})
            if body.get("lang") and body.get("lang") != "en":
                return httpx.Response(200, json={"success": False, "message": "lang 应为 en"})
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "result": [
                        {
                            "token": "hs-token",
                            "role": "admin",
                            "vsysId": "0",
                            "fromrootvsys": "true",
                            "username": user,
                        }
                    ],
                },
            )

        if path == "/rest/api/addrbook":
            self.locale_seen.add(request.headers.get("x-api-language"))
            if self.expire_once:
                self.expire_once = False
                return httpx.Response(
                    200,
                    json={"success": False, "error_code": "loginError_1003", "message": "会话已过期"},
                )
            if self.forbidden_once:
                self.forbidden_once = False
                return httpx.Response(403, json={"success": False, "message": "forbidden"})
            if request.headers.get("x-auth-token") != "hs-token":
                self.missing_auth += 1
                return httpx.Response(401, json={"success": False, "message": "unauthorized"})
            if self.require_plain and request.method in ("POST", "PUT"):
                content_type = request.headers.get("content-type") or ""
                if "application/json" in content_type:
                    return httpx.Response(415, json={"success": False, "message": "仅支持 text/plain"})
            if request.method == "GET":
                query = json.loads(request.url.params.get("query") or "{}")
                name = (query.get("conditions") or [{}])[0].get("value")
                items = []
                if name in self.groups:
                    items = [
                        {
                            "name": name,
                            "ip": [{"ip_addr": ip, "netmask": "32", "flag": 0} for ip in self.groups[name]],
                        }
                    ]
                return httpx.Response(200, json={"success": True, "result": items})
            body = json.loads(request.content)[0]
            name = body.get("name")
            ips = [item.get("ip_addr") for item in body.get("ip") or []]
            if request.method == "POST":
                if not self.ignore_block:
                    self.groups[name] = ips
                return httpx.Response(200, json={"success": True})
            if request.method == "PUT":
                if not self.ignore_block and not self.ignore_unblock:
                    self.groups[name] = ips
                return httpx.Response(200, json={"success": True})

        return httpx.Response(404, json={"success": False, "message": "not found"})


def expect(condition, message, failures) -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {message}")
    if not condition:
        failures.append(message)


def check_sangfor(spec, fake: FakeSangfor, failures) -> None:
    print("深信服 sangfor_af")
    expect(spec.capabilities["test"] and spec.capabilities["list_blocked"], "能力位由实现反推", failures)
    expect(tuple(spec.secret_fields) == ("password",), "敏感字段从清单推导", failures)
    cfg = {
        "base_url": "https://10.0.0.1",
        "username": "api-admin",
        "password": "secret",
        "namespace": "@namespace",
    }

    result = spec.call("test_connection")(cfg)
    expect(result.ok, f"test_connection 成功：{result.message}", failures)

    ctx = spec.call("setup")(cfg)
    spec.call("block")("10.1.1.1", cfg, ctx)
    expect("10.1.1.1" in fake.blocked, "block 写入黑名单", failures)
    before = len(fake.calls)
    spec.call("block")("10.1.1.1", cfg, ctx)
    expect(len(fake.calls) - before == 1, "重复 block 只查询一次、不重复下发", failures)
    expect(spec.call("list_blocked")(cfg) == ["10.1.1.1"], "list_blocked 返回已封禁 IP", failures)
    spec.call("unblock")("10.1.1.1", cfg, ctx)
    expect("10.1.1.1" not in fake.blocked, "unblock 解除封禁", failures)
    spec.call("teardown")(ctx)

    spec.call("block")("10.2.2.2", cfg, None)
    expect("10.2.2.2" in fake.blocked, "无会话时自行登录并封禁", failures)
    spec.call("unblock")("10.2.2.2", cfg, None)

    fake.login_fails = True
    try:
        spec.call("block")("10.3.3.3", cfg, None)
        expect(False, "登录失败应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.retryable is False, f"厂商拒绝标记为不可重试（{exc.code}）", failures)
    finally:
        fake.login_fails = False

    fake.network_down = True
    try:
        spec.call("block")("10.4.4.4", cfg, None)
        expect(False, "网络异常应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.retryable is True, f"网络异常标记为可重试（{exc.code}）", failures)
    finally:
        fake.network_down = False

    fake.ignore_block = True
    try:
        spec.call("block")("10.5.5.5", cfg, None)
        expect(False, "设备返回成功但复查未生效应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.code == "block_not_effective", f"复查未生效的失败码（{exc.code}）", failures)
        expect(exc.retryable is True, "复查未生效标记为可重试", failures)
    finally:
        fake.ignore_block = False

    spec.call("block")("10.6.6.6", cfg, None)
    fake.ignore_unblock = True
    try:
        spec.call("unblock")("10.6.6.6", cfg, None)
        expect(False, "设备返回成功但解封未生效应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.code == "unblock_not_effective", f"解封复查未生效的失败码（{exc.code}）", failures)
    finally:
        fake.ignore_unblock = False
    print()


def check_qianxin(spec, fake: FakeQianxin, failures) -> None:
    print("奇安信 qianxin_firewall")
    expect(spec.capabilities["test"] is True, "test_connection 能力位为真", failures)
    expect(spec.capabilities["list_blocked"] is False, "未实现 list_blocked 时能力位为假", failures)
    cfg = {"base_url": "https://10.0.0.2:8443", "username": "api-admin", "password": "secret"}

    result = spec.call("test_connection")(cfg)
    expect(result.ok, f"test_connection 成功：{result.message}", failures)

    ctx = spec.call("setup")(cfg)
    spec.call("block")("10.9.9.9", cfg, ctx)
    expect("10.9.9.9" in fake.blocked, "block 写入黑名单", failures)
    before = len(fake.calls)
    spec.call("block")("10.9.9.9", cfg, ctx)
    expect(len(fake.calls) - before == 1, "重复 block 只查询一次、不重复下发", failures)
    spec.call("unblock")("10.9.9.9", cfg, ctx)
    expect("10.9.9.9" not in fake.blocked, "unblock 解除封禁", failures)
    spec.call("teardown")(ctx)

    fake.calls.clear()
    spec.call("block")("10.8.8.8", cfg, None)
    expect("10.8.8.8" in fake.blocked, "无会话时自行登录并封禁", failures)
    expect(("/v1.0/out/" in [url for _, url in fake.calls]), "临时会话结束后退登", failures)
    print()


def check_topsec(spec, fake: FakeTopsec, failures) -> None:
    print("天融信 topsec_firewall")
    expect(spec.capabilities["test"] is True, "test_connection 能力位为真", failures)
    expect(spec.capabilities["list_blocked"] is False, "未实现 list_blocked 时能力位为假", failures)
    cfg = {"base_url": "https://10.0.0.3", "username": "api-admin", "password": "secret6"}

    result = spec.call("test_connection")(cfg)
    expect(result.ok, f"test_connection 成功：{result.message}", failures)

    # 登录：密码必须是设备要求的 AES-CBC 密文（密钥/偏移量 ngfwrestapilogin、零填充、base64）
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = base64.b64decode(fake.login_form.get("password", ""))
    decryptor = Cipher(
        algorithms.AES(b"ngfwrestapilogin"), modes.CBC(b"ngfwrestapilogin")
    ).decryptor()
    plain = (decryptor.update(cipher) + decryptor.finalize()).rstrip(b"\x00").decode()
    expect(plain == "secret6", "登录密码按设备要求 AES-CBC 加密", failures)
    expect(fake.login_form.get("pwdlen") == "7", "pwdlen 传明文密码长度", failures)
    expect(fake.login_form.get("name") == "api-admin", "登录传管理员名称", failures)

    fake.missing_cookie = fake.missing_code_run = fake.stale_token = 0
    ctx = spec.call("setup")(cfg)
    spec.call("block")("10.5.5.5", cfg, ctx)
    expect("10.5.5.5" in fake.blocked, "block 写入黑名单", failures)
    before = len(fake.calls)
    spec.call("block")("10.5.5.5", cfg, ctx)
    expect(len(fake.calls) - before == 1, "重复 block 只查询一次、不重复下发", failures)
    spec.call("unblock")("10.5.5.5", cfg, ctx)
    expect("10.5.5.5" not in fake.blocked, "unblock 解除封禁", failures)
    expect(fake.missing_cookie == 0, "非登录接口都带 Cookie", failures)
    expect(fake.missing_code_run == 0, "非登录接口都带 codeRun", failures)
    expect(fake.stale_token == 0, "使用上一次响应轮转出的 token", failures)
    spec.call("teardown")(ctx)

    fake.calls.clear()
    spec.call("block")("10.6.6.6", cfg, None)
    expect("10.6.6.6" in fake.blocked, "无会话时自行登录并封禁", failures)
    expect("/home/index/logout/" in [url for _, url in fake.calls], "临时会话结束后退登", failures)

    fake.login_fails = True
    try:
        spec.call("block")("10.7.7.7", cfg, None)
        expect(False, "登录失败应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.retryable is False, f"登录失败标记为不可重试（{exc.code}）", failures)
    finally:
        fake.login_fails = False
    print()


def check_nsfocus(spec, fake: FakeNsfocus, failures) -> None:
    print("绿盟 nsfocus_nf")
    expect(spec.capabilities["test"] and spec.capabilities["list_blocked"], "能力位由实现反推", failures)
    expect(tuple(spec.secret_fields) == ("api_token",), "敏感字段从清单推导", failures)
    cfg = {"base_url": "https://10.0.0.4:8081", "api_token": "gl-token"}

    result = spec.call("test_connection")(cfg)
    expect(result.ok, f"test_connection 成功：{result.message}", failures)

    fake.calls.clear()
    spec.call("block")("10.7.7.7", cfg, None)
    expect("10.7.7.7" in fake.entries.values(), "block 写入黑名单", failures)
    expect(
        ("POST", f"{FakeNsfocus.prefix}/configuration/") in fake.calls,
        "block 走 configuration 接口",
        failures,
    )
    gets = [path for method, path in fake.calls if method == "GET" and path == f"{FakeNsfocus.prefix}/info/"]
    expect(len(gets) == 2, f"block 前后各查一次做回读确认（实际 {len(gets)} 次）", failures)

    before = len(fake.calls)
    spec.call("block")("10.7.7.7", cfg, None)
    expect(len(fake.calls) - before == 1, "重复 block 只查询一次、不重复下发", failures)

    expect(spec.call("list_blocked")(cfg) == ["10.7.7.7"], "list_blocked 返回已封禁 IP", failures)

    fake.calls.clear()
    spec.call("unblock")("10.7.7.7", cfg, None)
    expect("10.7.7.7" not in fake.entries.values(), "unblock 解除封禁", failures)
    expect(bool(fake.delete_bodies and fake.delete_bodies[-1].get("id")), "删除按 id 下发", failures)

    # search 只回部分结果时回退全量查询，仍能判定「已封禁」而不重复下发
    spec.call("block")("10.11.11.11", cfg, None)
    fake.calls.clear()
    fake.truncate_search = True
    try:
        spec.call("block")("10.11.11.11", cfg, None)
        expect(
            len(fake.calls) == 2 and all(method == "GET" for method, _ in fake.calls),
            f"search 截断时回退全量查询（实际 {fake.calls}）",
            failures,
        )
    finally:
        fake.truncate_search = False

    fake.ignore_block = True
    try:
        spec.call("block")("10.5.5.5", cfg, None)
        expect(False, "下发后回读未见应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.code == "block_not_effective", f"回读未生效的失败码（{exc.code}）", failures)
        expect(exc.retryable is True, "回读未生效标记为可重试", failures)
    finally:
        fake.ignore_block = False

    spec.call("block")("10.6.6.6", cfg, None)
    fake.ignore_unblock = True
    try:
        spec.call("unblock")("10.6.6.6", cfg, None)
        expect(False, "解封未生效应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.code == "unblock_not_effective", f"解封未生效的失败码（{exc.code}）", failures)
    finally:
        fake.ignore_unblock = False

    try:
        spec.call("test_connection")({"base_url": cfg["base_url"], "api_token": "bad"})
        expect(False, "Token 无效应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.retryable is False, f"Token 无效标记为不可重试（{exc.code}）", failures)

    try:
        spec.call("block")("10.12.12.12", {"base_url": cfg["base_url"]}, None)
        expect(False, "缺少 Token 应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.code == "config_invalid", f"缺少 Token 的失败码（{exc.code}）", failures)

    fake.network_down = True
    try:
        spec.call("block")("10.4.4.4", cfg, None)
        expect(False, "网络异常应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.retryable is True, f"网络异常标记为可重试（{exc.code}）", failures)
    finally:
        fake.network_down = False
    print()


def check_hillstone(spec, fake: FakeHillstone, failures) -> None:
    print("山石网科 hillstone_fw")
    expect(spec.capabilities["test"] and spec.capabilities["list_blocked"], "能力位由实现反推", failures)
    expect(tuple(spec.secret_fields) == ("api_token", "password"), "敏感字段从清单推导", failures)
    cfg = {
        "base_url": "https://10.0.0.5:8443",
        "username": "api-admin",
        "password": "secret",
        "group_name": "SenseMind-Block",
    }

    result = spec.call("test_connection")(cfg)
    expect(result.ok and "尚不存在" in result.message, f"test_connection 组不存在时可用：{result.message}", failures)

    fake.calls.clear()
    spec.call("block")("10.20.0.1", cfg, None)
    expect(fake.groups.get("SenseMind-Block") == ["10.20.0.1"], "block 建组并写入 IP", failures)
    expect(
        ("POST", "/rest/api/addrbook") in fake.calls,
        "组不存在时走 POST 建组",
        failures,
    )
    expect(fake.missing_auth == 0, "地址簿请求都带会话头", failures)

    before = len(fake.calls)
    spec.call("block")("10.20.0.1", cfg, None)
    writes = [
        call
        for call in fake.calls[before:]
        if call[0] in ("POST", "PUT") and call[1] == "/rest/api/addrbook"
    ]
    expect(not writes, f"重复 block 不再下发写请求（实际 {writes}）", failures)

    spec.call("block")("10.20.0.2", cfg, None)
    expect(fake.groups.get("SenseMind-Block") == ["10.20.0.1", "10.20.0.2"], "组已存在时 PUT 追加", failures)
    expect(spec.call("list_blocked")(cfg) == ["10.20.0.1", "10.20.0.2"], "list_blocked 返回组内 IP", failures)

    spec.call("unblock")("10.20.0.1", cfg, None)
    expect(fake.groups.get("SenseMind-Block") == ["10.20.0.2"], "unblock 移出组", failures)
    spec.call("unblock")("10.20.0.1", cfg, None)
    expect(fake.groups.get("SenseMind-Block") == ["10.20.0.2"], "重复 unblock 幂等", failures)

    fake.ignore_block = True
    try:
        spec.call("block")("10.20.0.3", cfg, None)
        expect(False, "写入后回读未见应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.code == "block_not_effective", f"回读未生效的失败码（{exc.code}）", failures)
        expect(exc.retryable is True, "回读未生效标记为可重试", failures)
    finally:
        fake.ignore_block = False

    fake.ignore_unblock = True
    try:
        spec.call("unblock")("10.20.0.2", cfg, None)
        expect(False, "解封未生效应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.code == "unblock_not_effective", f"解封未生效的失败码（{exc.code}）", failures)
    finally:
        fake.ignore_unblock = False

    fake.login_fails = True
    try:
        spec.call("block")("10.20.0.4", cfg, None)
        expect(False, "登录失败应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.retryable is False, f"登录失败标记为不可重试（{exc.code}）", failures)
    finally:
        fake.login_fails = False

    # --- 认证约定（以 MCP 客户端实现为准）---
    expect("base64" in fake.login_modes, f"首选 base64 登录（实际 {fake.login_modes}）", failures)
    expect("plain" not in fake.login_modes, "设备接受 base64 时不再尝试明文", failures)
    expect(fake.locale_seen == {"en"}, f"请求带 X-API-Language=en（实际 {fake.locale_seen}）", failures)

    fake.reject_base64 = True
    fake.reject_plain = False
    fake.login_modes.clear()
    result = spec.call("test_connection")(cfg)
    expect(
        fake.login_modes[:2] == ["base64", "plain"],
        f"base64 被拒后退回明文（实际 {fake.login_modes}）",
        failures,
    )
    expect(result.ok, "明文兜底后仍可正常读组", failures)
    fake.reject_base64 = False
    fake.reject_plain = True

    token_cfg = {
        "base_url": "https://10.0.0.5:8443",
        "api_token": "hs-api-token",
        "group_name": "SenseMind-Block",
    }
    expect(spec.call("test_connection")(token_cfg).ok, "API Token 登录可用", failures)
    bad_token_cfg = dict(token_cfg, api_token="wrong")
    try:
        spec.call("block")("10.20.0.6", bad_token_cfg, None)
        expect(False, "Token 无效应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.code == "login_failed" and exc.retryable is False, f"Token 无效的失败码（{exc.code}）", failures)

    fake.expire_once = True
    logins_before = fake.logins
    spec.call("block")("10.20.0.9", cfg, None)
    expect(
        fake.logins > logins_before and "10.20.0.9" in fake.groups.get("SenseMind-Block", []),
        "loginError_1003 会话过期后自动重登并重试成功",
        failures,
    )

    # --- 与参考实现对齐的行为：403 清会话、text/plain 承载 JSON ---
    fake.forbidden_once = True
    logins_before = fake.logins
    spec.call("block")("10.20.0.10", cfg, None)
    expect(
        fake.logins > logins_before and "10.20.0.10" in fake.groups.get("SenseMind-Block", []),
        "HTTP 403 后自动重登并重试成功",
        failures,
    )

    fake.require_plain = True
    spec.call("block")("10.20.0.11", cfg, None)
    expect(
        "10.20.0.11" in fake.groups.get("SenseMind-Block", []),
        "HTTP 415 时改用 text/plain 重试成功",
        failures,
    )
    fake.require_plain = False

    fake.network_down = True
    try:
        spec.call("block")("10.20.0.5", cfg, None)
        expect(False, "网络异常应抛 DeviceError", failures)
    except DeviceError as exc:
        expect(exc.retryable is True, f"网络异常标记为可重试（{exc.code}）", failures)
    finally:
        fake.network_down = False
    print()


MINIMAL_DRIVER = '''
from sensemind_device import DeviceError, ProbeResult, check_ip

MANIFEST = {
    "key": "selftest_probe",
    "display_name": "自检临时设备",
    "schema_version": 1,
    "config_schema": [
        {"name": "base_url", "label": "管理地址", "type": "url", "required": True},
    ],
}


def test_connection(cfg):
    return ProbeResult(ok=True, message="selftest")


def block(ip, cfg, ctx=None):
    check_ip(ip)


def unblock(ip, cfg, ctx=None):
    check_ip(ip)
'''


def check_upload(failures) -> None:
    print("自定义脚本上传")
    name, source = registry.example_script()
    expect(name == "example_vendor.py" and "MANIFEST" in source, "示例脚本可读且含 MANIFEST", failures)

    for bad in ("../evil.py", "Evil.py", "9bad.py", "x.php", "a.py.py", "子.py", ""):
        try:
            registry.install_script(bad, MINIMAL_DRIVER.encode())
            expect(False, f"拒绝非法文件名 {bad!r}", failures)
        except registry.DriverLoadError:
            expect(True, f"拒绝非法文件名 {bad!r}", failures)

    cases = [
        ("probe_bin.py", b"\xff\xfe\x00MANIFEST", "非 UTF-8 文本"),
        ("probe_nul.py", MINIMAL_DRIVER.encode() + b"\x00", "NUL 字节"),
        ("probe_big.py", b"#" * (registry.MAX_SCRIPT_BYTES + 1), "超过体积上限"),
        ("probe_syntax.py", b"def broken(:\n", "语法错误"),
        ("probe_import.py", b"import subprocess\n" + MINIMAL_DRIVER.encode(), "白名单外的导入"),
        ("probe_os.py", b"import os\n" + MINIMAL_DRIVER.encode(), "导入 os"),
        ("probe_open.py", MINIMAL_DRIVER.encode() + b"\nopen('/etc/passwd').read()\n", "调用 open"),
        ("probe_dunder.py", MINIMAL_DRIVER.encode() + b"\nx = ().__class__\n", "双下划线属性"),
        ("probe_key.py", b"MANIFEST = {'key': 'other', 'display_name': 'x', 'schema_version': 1, 'config_schema': [{'name': 'a', 'label': 'a', 'type': 'text'}]}\n", "key 与文件名不一致"),
    ]
    for filename, content, label in cases:
        try:
            registry.install_script(filename, content)
            expect(False, f"拒绝{label}", failures)
        except registry.DriverLoadError:
            expect(True, f"拒绝{label}", failures)
        finally:
            (registry.CUSTOM_DIR / filename).unlink(missing_ok=True)

    target = registry.CUSTOM_DIR / "selftest_probe.py"
    try:
        spec = registry.install_script("selftest_probe.py", MINIMAL_DRIVER.encode(), uploaded_by="selftest")
        expect(spec.custom is True, "上传脚本标记为 custom", failures)
        expect(bool((spec.meta or {}).get("sha256")), "记录 sha256 元数据", failures)
        expect((spec.meta or {}).get("uploaded_by") == "selftest", "记录上传人", failures)
        expect("selftest_probe" in registry.scan(), "合法脚本安装后注册", failures)
        expect(target.exists(), "脚本落到 custom 目录", failures)

        try:
            registry.install_script("selftest_probe.py", MINIMAL_DRIVER.encode())
            expect(False, "同名脚本未确认覆盖应被拒绝", failures)
        except registry.DriverLoadError:
            expect(True, "同名脚本未确认覆盖被拒绝", failures)

        try:
            registry.install_script("qianxin_firewall.py", MINIMAL_DRIVER.encode())
            expect(False, "内置脚本不应允许上传覆盖", failures)
        except registry.DriverLoadError as exc:
            expect("内置脚本" in str(exc), "内置脚本不能被上传覆盖", failures)

        try:
            registry.uninstall_script("qianxin_firewall")
            expect(False, "内置脚本不应允许删除", failures)
        except registry.DriverLoadError as exc:
            expect("内置脚本" in str(exc), "内置脚本不能被删除", failures)

        registry.install_script("selftest_probe.py", MINIMAL_DRIVER.encode(), overwrite=True, uploaded_by="selftest")
        expect("selftest_probe" in registry.scan(), "确认覆盖后重新注册", failures)

        registry.uninstall_script("selftest_probe")
        expect("selftest_probe" not in registry.scan(), "删除自定义脚本后不再注册", failures)
    finally:
        target.unlink(missing_ok=True)
        for leftover in registry.UPLOAD_TMP_DIR.glob("**/*"):
            if leftover.is_file():
                leftover.unlink(missing_ok=True)
        meta = registry._read_meta()
        if meta.pop("selftest_probe", None) is not None:
            registry._write_meta(meta)
        registry.scan(force=True)
    print()


def check_store(spec, failures) -> None:
    """配置校验 → 加密落库 → 解密下发 → 读接口脱敏 的往返校验。"""
    print("设备配置存储（需要数据库）")
    from ..main import SessionLocal, engine
    from . import store
    from .models import ResponseDevice, create_response_tables

    create_response_tables(engine)
    db = SessionLocal()
    device = None
    try:
        values = store.validate_config(
            spec, {"base_url": "https://10.0.0.9", "username": "api-admin", "password": "p@ss"}
        )
        config, secret_fields = store.seal_config(spec, values)
        expect(str(config["password"]).startswith(store.SECRET_PREFIX), "敏感字段以 enc: 落库", failures)
        expect("p@ss" not in json.dumps(config), "明文密码不出现在存储内容里", failures)

        device = ResponseDevice(
            name="selftest-device",
            driver=spec.key,
            schema_version=spec.schema_version,
            config=config,
            secret_fields=secret_fields,
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        expect(store.runtime_config(device)["password"] == "p@ss", "运行时能解密出原文", failures)
        view = store.device_view(device, spec)
        expect("password" not in view["config"], "读接口不返回敏感字段", failures)
        expect(view["secret_configured"] == {"password": True}, "读接口只回是否已配置", failures)

        # 更新时密码留空应保留原值
        values2 = store.validate_config(
            spec, {"base_url": "https://10.0.0.9", "username": "api-admin"}, existing=device.config
        )
        config2, secret2 = store.seal_config(spec, values2, existing=device.config)
        expect(config2["password"] == config["password"], "敏感字段留空时保留原值", failures)
        expect(secret2 == secret_fields, "secret_fields 保持不变", failures)

        try:
            store.validate_config(spec, {"base_url": "https://x", "username": "u", "hack": 1})
            expect(False, "未知配置项应被拒收", failures)
        except Exception:
            expect(True, "未知配置项应被拒收", failures)
    finally:
        if device is not None and device.id is not None:
            db.delete(device)
            db.commit()
        db.close()
    print()


def main() -> int:
    failures = []
    sangfor = FakeSangfor()
    qianxin = FakeQianxin()
    topsec = FakeTopsec()
    nsfocus = FakeNsfocus()
    hillstone = FakeHillstone()

    def handler(request: httpx.Request):
        path = request.url.path
        if path.startswith("/v1.0/"):
            return qianxin.handle(request)
        if path.startswith("/home/"):
            return topsec.handle(request)
        if path.startswith("/north/"):
            return nsfocus.handle(request)
        if path.startswith("/rest/api/"):
            return hillstone.handle(request)
        return sangfor.handle(request)

    sensemind_device.set_transport_factory(lambda base_url: httpx.MockTransport(handler))

    specs = registry.scan(force=True)
    expect("sangfor_af" in specs, "registry 注册 sangfor_af", failures)
    expect("qianxin_firewall" in specs, "registry 注册 qianxin_firewall", failures)
    expect("topsec_firewall" in specs, "registry 注册 topsec_firewall", failures)
    expect("nsfocus_nf" in specs, "registry 注册 nsfocus_nf", failures)
    expect("hillstone_fw" in specs, "registry 注册 hillstone_fw", failures)
    order = [item["key"] for item in registry.manifests()]
    expect(
        order == ["qianxin_firewall", "sangfor_af", "topsec_firewall", "nsfocus_nf", "hillstone_fw"],
        f"下拉顺序按 MANIFEST.order（实际 {order}）",
        failures,
    )
    print()
    if failures:
        print(f"失败 {len(failures)} 项")
        return 1

    check_sangfor(specs["sangfor_af"], sangfor, failures)
    check_qianxin(specs["qianxin_firewall"], qianxin, failures)
    check_topsec(specs["topsec_firewall"], topsec, failures)
    check_nsfocus(specs["nsfocus_nf"], nsfocus, failures)
    check_hillstone(specs["hillstone_fw"], hillstone, failures)
    check_upload(failures)
    if os.environ.get("SENSEMIND_SELFTEST_DB") == "1":
        check_store(specs["sangfor_af"], failures)

    if failures:
        print(f"失败 {len(failures)} 项")
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
