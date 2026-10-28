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
                self.blocked.discard(ip)
                return httpx.Response(200, json={"code": 0, "message": "成功"})
        if path == f"{self.prefix}/whiteblacklist":
            if request.method == "POST":
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

    def handler(request: httpx.Request):
        path = request.url.path
        if path.startswith("/v1.0/"):
            return qianxin.handle(request)
        if path.startswith("/home/"):
            return topsec.handle(request)
        return sangfor.handle(request)

    sensemind_device.set_transport_factory(lambda base_url: httpx.MockTransport(handler))

    specs = registry.scan(force=True)
    expect("sangfor_af" in specs, "registry 注册 sangfor_af", failures)
    expect("qianxin_firewall" in specs, "registry 注册 qianxin_firewall", failures)
    expect("topsec_firewall" in specs, "registry 注册 topsec_firewall", failures)
    print()
    if failures:
        print(f"失败 {len(failures)} 项")
        return 1

    check_sangfor(specs["sangfor_af"], sangfor, failures)
    check_qianxin(specs["qianxin_firewall"], qianxin, failures)
    check_topsec(specs["topsec_firewall"], topsec, failures)
    if os.environ.get("SENSEMIND_SELFTEST_DB") == "1":
        check_store(specs["sangfor_af"], failures)

    if failures:
        print(f"失败 {len(failures)} 项")
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
