# 设备接入指南

面向需要把防火墙接入「联动外发 → 联动处置」的使用者与开发者。

> 已内置：`qianxin_firewall.py`（奇安信防火墙）、`sangfor_af.py`（深信服防火墙）、`topsec_firewall.py`（天融信防火墙），接入要点见第二节。
> 新增厂商设备按第三节脚本契约写一个 `.py` 文件，落地步骤见第六节。

---

## 目录

- [一、页面操作流程](#一页面操作流程)
- [二、内置设备接入指导](#二内置设备接入指导)
  - [2.1 设备侧账号怎么开（通用）](#21-设备侧账号怎么开通用)
  - [2.2 奇安信防火墙](#22-奇安信防火墙qianxin_firewallpy)
  - [2.3 深信服防火墙](#23-深信服防火墙sangfor_afpy)
  - [2.4 天融信防火墙](#24-天融信防火墙topsec_firewallpy)
- [三、脚本契约（ABI v1）](#三脚本契约abi-v1)
  - [3.1 文件名与清单](#31-文件名与清单)
  - [3.2 config_schema 字段描述符](#32-config_schema-字段描述符)
  - [3.3 函数](#33-函数)
  - [3.4 错误语义](#34-错误语义)
- [四、sensemind_device 公共模块](#四sensemind_device-公共模块)
- [五、骨架示例](#五骨架示例)
- [六、落地与验证](#六落地与验证)
- [七、排错](#七排错)
- [八、技术约束](#八技术约束)

---

## 一、页面操作流程

入口：侧栏 **联动外发**（`/outbound`）。页面顶部是两个 tab：**联动处置**（邮件告警 + 联动设备/联动设置/IP 白名单）与 **联动日志**。

1. **添加联动设备**：联动处置板块右上角 → 选设备类型（下拉项来自已注册脚本）→ 按脚本声明的字段填写 → 「测试连接」确认可达 → 保存。
2. **测试连接**：未保存的配置调 `POST /api/v1/response/devices/test`（按当前表单值临时连一次）；已保存的设备在列表点「测试连接」调 `POST /api/v1/response/devices/{id}/test`（用库中已加密的配置）。
3. **添加联动处置**：把「设备」与「命中条件」绑定。「命中条件」取自分析中心的**快捷检索**（`AlertSearchPreset`，只用 `is_enabled=true` 的）。绑定关系确定后，命中该检索条件的告警由平台把源 IP 下发到所绑设备封堵。
4. **IP 白名单**：命中的源 IP 若在白名单内则跳过封堵，支持单 IP 与 CIDR。
5. **手动处置**：分析中心告警详情右上角「处置」→ 勾选源地址/目的地址 → 选一台已启用设备 → 下发封堵（`POST /api/v1/response/actions`，一次一个 IP）。**处置成功后会把原告警文档标记 `blocked=true`**（写入参数 `event_id` + `event_index`，失败不标记；标记没写成功时接口会明确返回 `event_blocked=false`）。
6. **联动日志**：每次下发都留一行记录，成功/失败都记，失败带设备返回的错误原因；白名单命中的跳过不记。列表支持按**处置地址**（模糊）、**动作**（封堵/解封）、**处置结果**、**联动设备**筛选。**封堵成功**的记录可点「撤销」：设备侧解封，并另记一条 `unblock` 日志（原记录不改写）。

字段与状态的落地规则：

| 项 | 规则 |
| --- | --- |
| 敏感字段 | `secret: true` 的字段落库前用 `ENCRYPT_KEY` 加密，存量值为 `enc:` 前缀；读接口只回 `secret_configured`，不回明文 |
| 敏感字段留空 | 编辑时留空 = 沿用旧值，不会被清空 |
| 未知配置项 | 提交清单外的键直接 400（`未知配置项：xxx`），避免拼错字段静默失效 |
| 类型强转 | `int` / `bool` / `select` 由平台按 `type` 与 `choices` 校验后强转 |
| 驱动类型 | 设备保存后不可改（改驱动会让存量 `config` 语义错位），需删了重建 |
| 设备删除 | 被联动处置引用时返回 409，先解绑 |

---

## 二、内置设备接入指导

### 2.1 设备侧账号怎么开（通用）

两家设备的账号体系不同：

- **奇安信防火墙**：有**独立的 RESTful API 账号体系**。必须先启用 RESTful API，再建角色为「RESTful API管理员」的账号，普通 WebUI 管理员账号不能替代（见 2.2）。
- **深信服防火墙**：没有独立的 API 角色，API 调用的就是设备本地**管理员账户**，按角色权限模板授权（见 2.3）。

**无论哪种设备，都新建专用账号给平台用，不要复用默认 `admin`**。理由：

- 权限最小化：封堵只需要「对象/地址黑名单」模块的读写权限，不需要策略下发、系统升级、配置备份权限。
- 审计可分：设备侧操作日志能区分「平台自动封堵」与「人工操作」。
- 故障隔离：专用账号被密码策略锁定（多次登录失败）时不影响人工登录设备。
- 改密影响面小：轮换这个密码只影响平台侧一条设备配置。

建账号时注意：

| 项 | 要求 |
| --- | --- |
| 权限 | 只授予「地址黑名单 / 地址对象」读写权限；只读角色会在封堵时才报权限错误 |
| 登录来源限制 | 若设备限制了登录的源地址，须把 `alert-responder` 容器的出口 IP（或 Docker 网桥网段）加入允许列表，否则登录被直接拒绝 |
| 双因素 / 短信验证 | 必须对该账号关闭，否则拿不到可用会话 |
| 密码策略 | 关闭「首次登录强制改密」与过期提醒；密码用 12 位以上强密码，保存后由平台加密存储 |
| 证书 | 设备管理口多为自签证书，页面「高级选项」里保持「校验证书」关闭（默认已关）；若使用内部 CA，可保持开启并填 `ca_cert_pem` |

### 2.2 奇安信防火墙（`qianxin_firewall.py`）

字段与填写：

| 字段 | 说明 |
| --- | --- |
| 管理地址 | 含协议与端口，如 `https://10.0.0.1:8443`；也有 `http://<ip>:8080` 的部署，按设备实际填 |
| 用户名 / 密码 | **RESTful API 账号**（不是普通 WebUI 管理员） |

账号准备（三步，均在设备 WebUI 完成）：

1. **启用 RESTful API**：`系统配置` → `设备管理` → `本机设置` → `RESTful API`，开启后接口才可访问。
2. **新建 RESTful API 用户**：`系统配置` → `设备管理` → `管理账号` → 新建账号，角色选 **`RESTful API管理员`**。账号名任意（示例用 `api-admin`）；接口权限按该角色模板授予，换成普通 WebUI 管理员角色可能缺少 API 调用权限。
3. **添加可信主机**（设备启用了「管理主机」时必须做）：`系统配置` → `设备管理` → `管理主机` → 添加可信主机，添加时选择 **RESTful API** 类型，并填入 `alert-responder` 所在服务器的出口 IP。

接口调用顺序（脚本已实现）：

1. `POST /v1.0/login`，body `{"username": ..., "password": ...}` → 返回 `__s_sessionid__` cookie 与 `result.token`。
2. 业务请求统一 `POST /v1.0/rest/`，body 为列表，用 `head.module` + `head.function` 分发，成功判据是 `head.error_code` 为 0。
3. 结束 `POST /v1.0/out/` 退登。

封堵写入的位置是 **`策略配置` → `黑白名单` → `地址黑名单`**（`module=addr_blacklist`），三条 function：

| 动作 | function | body 要点 |
| --- | --- | --- |
| 查是否已存在 | `get_blacklist_config` | `{"addr_blacklist_cp": {"search_key": "<ip>", "is_detail": "true"}}`；`search_key` 支持模糊匹配，须按返回的 `ip_start`/`ip_end` 精确比对 |
| 添加 | `add_blacklist_ip_web` | `blacklist_cp[{name, type:"host", ip_start, ip_end, enable:"enable", desc, schedule:""}]`，`name` 取 `sm-<ip>` |
| 删除 | `del_blacklist_by_id` | `blacklist_cp[{ip_start, ip_end}]`。传 `name` 或 `id` 也返回 `error_code=0`，但条目不会被删，必须传起止地址 |

规格限制：地址黑名单上限 **1000 条**，且添加接口不支持批量下发（一次一条）。封堵规模会超过这个量时，需改用「批量黑IP封堵」（`add_batch_blacklist`，每次最多 1000 个），该名单是独立的阻断入口。

能力位：`test` = true（连接测试为登录 + 退登），`list_blocked` = false，`ipv6` = false。

### 2.3 深信服防火墙（`sangfor_af.py`）

字段与填写：

| 字段 | 说明 |
| --- | --- |
| 管理地址 | 含协议与端口，如 `https://10.0.0.1:443` |
| 用户名 / 密码 | 设备管理员账户 |
| 命名空间 | 默认 `@namespace`，单机部署不用动；只有设备开了多虚拟系统才需要填实际命名空间。它对应接口路径里的 `/api/v1/namespaces/<命名空间>/...` 这一段，`@namespace` 就是根系统的固定标识 |

账号准备：AF 的管理员账号就是 API 账号（设备侧 `/api/v1/namespaces/{ns}/account` 即管理员账户管理接口，`modulepermissiontpl` 查各角色的默认权限模板）。建议新建专用管理员账户并分配含「对象 / 黑名单」权限的角色，不要复用默认 `admin`；多虚拟系统场景下该账号需在所填命名空间内存在。

接口调用顺序（脚本已实现）：

1. `POST /api/v1/namespaces/{ns}/login`，body `{"name": ..., "password": ...}` → `data.loginResult.token`，后续请求带 `Cookie: token=<token>`。
2. 黑名单：`POST/DELETE/GET .../whiteblacklist`，body `{"type": "BLACK", "url": "<ip>", "enable": true, "description": "SenseMind联动封禁"}`。
3. 结束 `POST /api/v1/namespaces/{ns}/logout`。

判成功不能只看 `message == "成功"`，须与 `code` 一起判（两者任一为成功态即视为成功）。封堵前先 `GET .../whiteblacklist/<ip>`，已在黑名单则跳过；解封时 IP 不存在同样视为成功（幂等）。`list_blocked` 已实现，按 `data.totalPages` 每页 200 翻页。

### 2.4 天融信防火墙（`topsec_firewall.py`）

字段与填写：

| 字段 | 说明 |
| --- | --- |
| 管理地址 | 含协议与端口，如 `https://10.0.0.1:443` |
| 用户名 / 密码 | 设备管理员账号；密码填**明文**，脚本按设备要求自行加密后提交 |

账号准备：用设备管理员账号，需具备「资源管理 → 黑名单传播」的读写权限。设备若启用了**登录验证码**须关闭，平台走免验证码登录接口 `/home/login/addNoCode/`。

调用约定（官方文档「注意事项 → 统一参数获取」）：

1. **登录** `POST /home/login/addNoCode/`，表单 `name` + `password` + `pwdlen`。密码用 AES-CBC（密钥与偏移量均为 `ngfwrestapilogin`、零填充、输出 base64），`pwdlen` 是明文长度。响应正文是 base64 JSON：`data.authid` 作为 userMark，`data.secret` 参与 codeRun 计算。
2. **公共参数**：除登录外每个请求都必须带登录返回的 Cookie、`Referer: <base>/html/webui/home.html/?userMark=<userMark>`、`Content-Type: application/x-www-form-urlencoded`。
3. **token**：取响应里 `?[` 与 `}?` 之间的字符串；**每次请求都会换新的**，下一次请求必须用最新的。
4. **codeRun** = `md5(secret + token + url + commands 的 JSON)`。
5. **封堵落点**：`资源管理` → `黑名单传播`（`blackListSpread`），按五元组下发：

| 动作 | 请求 |
| --- | --- |
| 查是否已存在 | `GET /home/default/blackListSpread/searchpf/?commands[0][pf_blacklist_static_search][0]=<ip>` |
| 添加 | `POST /home/default/blackListSpread/add/`，`commands[0][pf_blacklist_add][sip]=<ip>` |
| 删除 | `POST /home/default/blackListSpread/deleteLots/`，`commands[0][pf_blacklist_delete][0][sip]=<ip>`（其余四元组字段传空串） |

6. **判成功**：响应 `{"result":true,...}`；`{"result":false,"data":"原因"}` 为失败。查询结果在 `rows[]` 里，五元组记录看 `sip`、地址段记录看 `ip_start`/`ip_end`。

能力位：`test` = true，`list_blocked` = false，`ipv6` = false。

---

## 三、脚本契约（ABI v1）

**ABI v1 是什么**：ABI（Application Binary Interface）指两段程序之间的调用约定。这里借指「平台 ↔ 设备脚本」之间的契约——脚本需要暴露哪些模块级常量、哪些函数、参数与返回结构是什么、错误怎么表达。`v1` 是当前契约的版本号，对应公共模块里的 `sensemind_device.API_VERSION = 1`；将来若做不兼容变更（例如要求 `block` 支持批量下发），平台会递增版本并短暂同时支持新旧两版，脚本若自己声明了 `API_VERSION` 就必须与平台一致，否则拒绝加载。按本文写出来的脚本都符合 v1。

注册表 `app/response/registry.py` 启动时扫描 `devices/*.py`（跳过 `_` 开头的文件），逐个校验；**任何不合规直接加载失败并记 ERROR 日志，不静默跳过**。

### 3.1 文件名与清单

文件名（不含 `.py`）= `MANIFEST["key"]`，不一致即加载失败。

```python
MANIFEST = {
    "key": "vendor_x",                  # 必须与文件名一致，全局唯一
    "display_name": "厂商 X 防火墙",     # 前端下拉与列表显示
    "schema_version": 1,                # >=1 的整数；同一 key 的字段结构变更时递增
    "config_schema": [ ... ],           # 非空列表，见 3.2
    "capabilities": {"ipv6": False},    # 只有 ipv6 需要显式声明
}
```

`MANIFEST` 必需键：`key`、`display_name`、`schema_version`、`config_schema`。

可选模块级常量 `API_VERSION`：不写则视为与平台一致；写了就必须等于平台值（当前 `1`），否则加载失败。**接口不兼容变更时平台递增该值，旧脚本会被拒绝加载**——这是有意的，避免封堵时才炸。

### 3.2 config_schema 字段描述符

```python
{
    "name": "base_url",          # 必需，cfg 中的键名
    "label": "管理地址",          # 必需，表单标签与错误提示用
    "type": "url",               # 必需，见下表
    "required": True,            # 必填（敏感字段编辑时留空不算缺失）
    "default": "https://10.0.0.1:8443",  # 新建时的初始值
    "placeholder": "https://10.0.0.1:8443",
    "help": "含协议，端口按设备实际填写",  # 表单项下方灰色说明
    "secret": True,              # 敏感字段：加密落库、读取不回显
    "choices": ["A", "B"],       # type=select 时必需
    "depends_on": {"mode": "api"},  # 单层条件显隐：mode 的值等于 api 时才显示
}
```

`type` 取值：`text`、`password`、`url`、`int`、`bool`、`select`、`textarea`。`select` 未给 `choices` 会加载失败；`depends_on` 只支持单层对象（不支持嵌套/多值）。

**平台保留字段名，脚本不得声明**（声明即加载失败）：`timeout_seconds`、`verify_tls`、`ca_cert_pem`、`max_concurrency`。这四项由页面「高级选项」统一渲染、由 `sensemind_device.http_client()` 统一消费：

| 平台字段 | 默认值 | 作用 |
| --- | --- | --- |
| `timeout_seconds` | 10 | 单次 HTTP 超时 |
| `verify_tls` | `False` | 是否校验证书；自签证书设备须关闭 |
| `ca_cert_pem` | `""` | 自定义 CA（PEM 文本），仅 `verify_tls=True` 时生效 |
| `max_concurrency` | 4 | 平台侧并发上限 |

### 3.3 函数

必需（缺一即加载失败）：

```python
def block(ip: str, cfg: dict, ctx=None) -> None:
    """封堵单个 IP；失败必须抛 DeviceError，禁止静默返回。"""

def unblock(ip: str, cfg: dict, ctx=None) -> None:
    """解除封堵；IP 本来不在黑名单时应视为成功（幂等）。"""
```

可选（有则自动置对应能力位）：

```python
def setup(cfg: dict) -> dict:
    """建立会话（登录换 token 等），返回值原样作为 ctx 传给 block/unblock；不要返回明文凭据日志。"""

def teardown(ctx) -> None:
    """释放 setup 申请的资源（退登、关连接）。block 抛异常时也必须被调用。"""

def test_connection(cfg: dict) -> ProbeResult:
    """连接测试，给页面「测试连接」回显。"""

def list_blocked(cfg: dict) -> list[str]:
    """返回设备当前封堵的 IP 列表；分页参数未核验时不要实现，宁可不报该能力。"""
```

能力位由实现反推，不在清单里声明，避免「声明了但函数没写」：

- `capabilities.test` = 是否有 `test_connection`
- `capabilities.list_blocked` = 是否有 `list_blocked`
- `capabilities.ipv6` = `MANIFEST["capabilities"]["ipv6"]`

调用约定：

- **单 IP 粒度**。批量由平台循环、逐 IP 落封堵记录，脚本不要自己拼批量请求。
- `cfg` 由平台构造并解密后传入，**脚本不读环境变量、不自己存凭据**。
- 有 `setup` 时，平台在同批次的多次 `block` 之间复用同一个 `ctx`，减少重复登录；`block` 内若无 `ctx` 应能自行登录一次并在结束时退出。
- 函数内 `import` 只允许 `sensemind_device` + 标准库 + `httpx`。**不 import 其他设备脚本、不引厂商 SDK**。

### 3.4 错误语义

```python
from sensemind_device import DeviceError

raise DeviceError("vendor_rejected", f"添加黑名单失败：{msg}", retryable=False, status=400)
```

- `code`：稳定的短标识（`timeout` / `network` / `http_error` / `login_no_token` / `vendor_rejected` / `invalid_ip` …），可用于排错统计。
- `retryable`：**只有网络中断、超时、5xx、429 才为 `True`**。厂商业务码拒绝、4xx、凭据错误一律 `False`——否则重试只会重复打设备。
- 返回 `ProbeResult(ok=True|False, message=..., detail={...})` 用于连接测试回显；连接测试失败也可以直接抛 `DeviceError`，平台会转成 `{ok: false, code, retryable}`。

---

## 四、sensemind_device 公共模块

脚本只依赖这一个模块（`alert-responder/sensemind_device/`）。

| API | 说明 |
| --- | --- |
| `http_client(cfg, *, cookies=None, headers=None, timeout=None)` | 按 `base_url` 建 `httpx.Client`，自动消费 `timeout_seconds` / `verify_tls` / `ca_cert_pem`，不跟随重定向 |
| `send(client, method, url, **kwargs)` | 发请求，把 `httpx` 超时/网络异常收敛成 `DeviceError(retryable=True)` |
| `status_error(response, *, message="")` | HTTP 层失败分类：5xx/429 可重试，其余不可重试 |
| `json_body(response, *, code="bad_response")` | 取响应 JSON 对象，非法 JSON 转 `DeviceError` |
| `json_after_token(response, *, code="bad_response")` | 先切 `?[TOKEN}?` 前缀再解析 JSON（WebUI 表单类接口） |
| `split_token_prefix(text)` | 返回 `(token, 剩余正文)`，用于手工切前缀 |
| `check_ip(value)` | 校验并规范化单个 IP，非法抛 `DeviceError("invalid_ip")`；**不接受 CIDR** |
| `check_network(value)` | 校验并规范化 CIDR，用于白名单类接口 |
| `logger(name)` | 返回带 `sensemind_device.<name>` 上下文的 logger，接到平台日志 |
| `mask(value)` / `mask_config(cfg)` | 脱敏，仅供日志 |
| `DeviceError` / `ProbeResult` | 见 3.4 |
| `set_transport_factory(factory)` | 仅测试用（注入 `httpx.MockTransport`），正常运行不要调用 |
| `API_VERSION` | 当前 `1` |

约束：

- **不要用 `print`**，日志走 `logger(...)`，否则容器日志里分不清是哪个驱动。
- **不要在脚本里处理超时与 TLS**，否则会出现「某个调用点忘了带校验」的漏口。
- 日志里不要出现明文密码/token；打印完整配置用 `mask_config(cfg)`。

---

## 五、骨架示例

```python
"""厂商 X 防火墙（一个设备一个文件）。

接口要点：POST /login 拿 token → 后续请求头带 X-Token → 黑名单 /api/blocklist 增删。
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
    "key": "vendor_x",
    "display_name": "厂商 X 防火墙",
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
    "capabilities": {"ipv6": False},
}

log = logger("vendor_x")
DESCRIPTION = "SenseMind联动封禁"


def _login(cfg: dict):
    client = http_client(cfg)
    response = send(
        client,
        "POST",
        "/login",
        json={"username": cfg.get("username"), "password": cfg.get("password")},
    )
    if response.status_code >= 400:
        client.close()
        raise status_error(response, message="登录请求被拒绝")
    token = (json_body(response).get("data") or {}).get("token")
    if not token:
        client.close()
        raise DeviceError("login_no_token", "登录成功但未返回 token", retryable=False)
    client.headers["X-Token"] = token
    return client


@contextmanager
def _session(cfg: dict, ctx):
    """有 setup 提供的会话就复用，否则临时登录并在结束时关闭。"""
    if ctx and ctx.get("client") is not None:
        yield ctx["client"]
        return
    client = _login(cfg)
    try:
        yield client
    finally:
        client.close()


def setup(cfg: dict) -> dict:
    return {"client": _login(cfg)}


def teardown(ctx) -> None:
    if ctx and ctx.get("client") is not None:
        send(ctx["client"], "POST", "/logout")   # 失败不应影响主流程时自行 try/except
        ctx["client"].close()


def test_connection(cfg: dict) -> ProbeResult:
    ctx = setup(cfg)
    teardown(ctx)
    return ProbeResult(ok=True, message="登录成功")


def block(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    with _session(cfg, ctx) as client:
        response = send(
            client,
            "POST",
            "/api/blocklist",
            json={"ip": target, "description": DESCRIPTION},
        )
        if response.status_code >= 400:
            raise status_error(response, message="添加封堵失败")
        payload = json_body(response)
        if payload.get("code") not in (0, "0"):
            # 已存在应视为成功（幂等），这里只处理真正的业务拒绝
            raise DeviceError(
                "vendor_rejected",
                f"添加封堵失败：{payload.get('msg') or '设备未返回原因'}",
                retryable=False,
                status=response.status_code,
            )


def unblock(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    with _session(cfg, ctx) as client:
        response = send(client, "DELETE", f"/api/blocklist/{target}")
        if response.status_code == 404:
            log.info("IP 不在封堵列表，跳过：%s", target)   # 幂等
            return
        if response.status_code >= 400:
            raise status_error(response, message="解除封堵失败")
```

---

## 六、落地与验证

1. 把脚本放进 `alert-responder/app/response/devices/`（代码打进镜像，无 bind mount）：

   ```bash
   sudo docker compose -f /home/zdby/SenseMind/docker-compose.yml up -d --build alert-responder
   ```

2. 看是否注册成功（加载失败只记日志，页面下拉里不会出现该项）：

   ```bash
   sudo docker logs alert-responder 2>&1 | grep -E "设备脚本加载失败|设备脚本 key 重复"
   ```

3. 跑自检（用 `MockTransport` 打全链路，不需要真实设备，也覆盖内置两家）：

   ```bash
   sudo docker exec alert-responder python -m app.response.selftest
   sudo docker exec -e SENSEMIND_SELFTEST_DB=1 alert-responder python -m app.response.selftest   # 含存储层
   ```

4. 页面确认：联动外发 → 添加联动设备，下拉里能看到 `display_name`，表单字段与 `config_schema` 一致（`depends_on` 字段随上游选择显隐）。

5. 真机顺序：先「测试连接」（只验证登录/握手）→ 再建一条联动处置，用白名单外的测试 IP 走一次封堵 → 在设备侧核对黑名单条目与描述 → 解除封堵确认幂等。

---

## 七、排错

| 现象 | 原因与处理 |
| --- | --- |
| 下拉里没有新设备类型 | 脚本加载失败：查第三节日志，通常是 `MANIFEST.key` 与文件名不一致、`config_schema` 缺 `name/label/type`、`select` 缺 `choices`、声明了平台保留字段名 |
| 表单里某字段不显示 | 该字段有 `depends_on`，上游字段当前值不匹配 |
| 保存报 `未知配置项` | 提交了清单外的键；加字段要改脚本 `config_schema` 并递增 `schema_version` |
| 保存报 `缺少必填项` | 新建时必填项为空；编辑时仅敏感字段允许留空沿用旧值 |
| 设备凭据无法解密 | `ENCRYPT_KEY` 变了（换了 `.env`），需在页面重新保存该设备配置 |
| 测试连接超时 | 自签证书设备须关「校验证书」；确认 `alert-responder` 容器到设备管理口的路由与端口放通 |
| 登录被拒绝或返回权限不足 | 奇安信：未启用 RESTful API、用了普通 WebUI 管理员账号（须为 `RESTful API管理员` 角色），或启用了「管理主机」但平台服务器 IP 未加为可信主机（RESTful API）；两家通用：账号未授予地址黑名单模块权限，或设备限制了登录来源 IP，见 2.1 |
| 封堵成功但设备侧无记录 | 脚本把厂商业务失败当成功了；成功判据要与厂商文档一致（不能只看 `message`，常需配合 `code`/`error_code`） |
| 重复重试打爆设备 | 厂商业务拒绝被标成了 `retryable=True` |

---

## 八、技术约束

- 传输层只有 HTTP/HTTPS；只提供 CLI/SSH 处置入口的设备不适用本契约。
- `block` 只接受单 IP，不支持一次批量下发；`unblock` 必须幂等。
- 脚本以文件形式随镜像分发（无 bind mount），新增或修改脚本都要随镜像重建才生效。
- IPv6 支持需设备与脚本两侧都满足（`capabilities.ipv6`），默认关闭。
- 一台设备对应一条配置记录；同一物理设备上的多个虚拟系统按不同命名空间建多条记录。
