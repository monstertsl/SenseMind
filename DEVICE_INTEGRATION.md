# 设备接入指南

面向要把防火墙（或任何能做 IP 阻断的设备）接入「联动外发 → 联动处置」的使用者与开发者。

> 已内置：`qianxin_firewall.py`（奇安信防火墙）、`sangfor_af.py`（深信服防火墙）、`topsec_firewall.py`（天融信防火墙）、`nsfocus_nf.py`（绿盟 NF 防火墙）、`hillstone_fw.py`（山石网科防火墙），接入要点见第九节。
> 内置设备类型覆盖不到的厂商，自己写一份脚本上传即可——不用改平台代码、不用重启服务，写法见第三、四节，踩坑清单见第五节。

---

## 目录

- [一、快速开始](#一快速开始)
- [二、可用库与运行环境](#二可用库与运行环境)
  - [2.1 脚本在哪里运行](#21-脚本在哪里运行)
  - [2.2 导入白名单（硬限制）](#22-导入白名单硬限制)
  - [2.3 禁止的内建与语法](#23-禁止的内建与语法)
  - [2.4 sensemind_device 全部 API](#24-sensemind_device-全部-api)
- [三、脚本规范](#三脚本规范)
  - [3.1 文件命名与 MANIFEST](#31-文件命名与-manifest)
  - [3.2 配置字段描述符](#32-配置字段描述符)
  - [3.3 函数约定](#33-函数约定)
  - [3.4 错误与 retryable](#34-错误与-retryable)
- [四、完整模板](#四完整模板)
- [五、实战经验与常见坑](#五实战经验与常见坑)
- [六、上传、生效与安全边界](#六上传生效与安全边界)
  - [6.1 页面操作](#61-页面操作)
  - [6.2 上传时的校验](#62-上传时的校验)
  - [6.3 覆盖、删除与已保存设备的关系](#63-覆盖删除与已保存设备的关系)
  - [6.4 恶意脚本的风险与边界](#64-恶意脚本的风险与边界)
- [七、验证清单](#七验证清单)
- [八、故障排查](#八故障排查)
- [九、内置设备类型接入说明](#九内置设备类型接入说明)
  - [9.1 设备侧账号准备（通用）](#91-设备侧账号准备通用)
  - [9.2 奇安信防火墙](#92-奇安信防火墙)
  - [9.3 深信服防火墙](#93-深信服防火墙)
  - [9.4 天融信防火墙](#94-天融信防火墙)
  - [9.5 绿盟 NF 防火墙](#95-绿盟-nf-防火墙)
  - [9.6 山石网科防火墙](#96-山石网科防火墙)
- [十、设计与约束](#十设计与约束)

---

## 一、快速开始

入口：侧栏 **联动外发**（`/outbound`）。页面顶部两个 tab：**联动处置**（联动设备 / 联动设置 / IP 白名单）与 **联动日志**。

两条接入路径：

| 路径 | 适用 | 成本 |
| --- | --- | --- |
| 直接用内置设备类型 | 设备在第九节列表里 | 只填地址和账号，几分钟 |
| 自己写脚本上传 | 厂商不在列表、或需要接自有系统 | 写一个 100~300 行的 `.py`，不需要重启 |

自定义脚本的最短路径：

1. **联动处置** → 「添加联动设备」→ 点「下载示例脚本」，得到 `example_vendor.py`。
2. 改文件名为 `<vendor>_device.py`（如 `fortinet_fw.py`），并把 `MANIFEST["key"]` 改成同名（去掉 `.py`）。
3. 按厂商文档改 `MANIFEST["config_schema"]`、登录逻辑与 `block`/`unblock`（规范见第三节，坑见第五节）。
4. 点「上传设备脚本」选择该文件。上传成功后设备类型下拉自动刷新并选中新设备类型。
5. 填配置 → 「测试连接」确认能登录 → 保存。
6. 建一条「联动处置」，用白名单外的测试 IP 走一次封堵，去设备侧核对。

字段与状态的落地规则：

| 项 | 规则 |
| --- | --- |
| 敏感字段 | `secret: true` 的字段落库前用 `ENCRYPT_KEY` 加密，存量值为 `enc:` 前缀；读接口只回 `secret_configured`，不回明文 |
| 敏感字段留空 | 编辑时留空 = 沿用旧值，不会被清空 |
| 未知配置项 | 提交清单外的键直接 400（`未知配置项：xxx`），避免拼错字段静默失效 |
| 类型强转 | `int` / `bool` / `select` 由平台按 `type` 与 `choices` 校验后强转 |
| 设备类型 | 设备保存后不可改（换类型会让存量 `config` 语义错位），需删了重建 |
| 设备删除 | 被联动处置引用时返回 409，先解绑 |

---

## 二、可用库与运行环境

写脚本前先读这一节。上传脚本有硬性限制，**照抄内置脚本不一定能过**。

### 2.1 脚本在哪里运行

| 事实 | 说明 |
| --- | --- |
| 执行位置 | `alert-responder` 服务进程内（CPython 3.12），**不是**独立进程 |
| 权限 | 与平台完全相同：能读到进程环境变量（数据库口令、`ENCRYPT_KEY`）、能访问容器网络。参见 6.4 |
| 模块名 | 加载时模块名固定为 `sensemind_device_drivers.<key>` |
| 相对导入 | **不可用**。`from . import x` 会在静态检查阶段被拒绝（模块名为空，不在白名单） |
| 生效方式 | 上传成功即热加载（`scan(force=True)`），不需要重启；覆盖上传后已保存的设备立即用新实现 |
| 单次执行 | 一次 `block` 调用 = 一个 IP。批量由平台循环，脚本不要自己拼批量 |

想在本地先把脚本跑通再上传：把 `alert-responder/sensemind_device/` 整个目录拷到脚本同级，`import sensemind_device` 后即可用；需要假响应时用 `httpx.MockTransport` 配合 `set_transport_factory()` 注入。这两样只写在**本地测试代码**里——上传的脚本不许 `import httpx`，也不许调用 `set_transport_factory()`。

### 2.2 导入白名单（硬限制）

平台用 `ast` 静态扫描脚本里的每一条 `import` / `from ... import`（**函数体里的也算**），只有下面 24 个模块可以通过：

| 模块 | 典型用途 | 模块 | 典型用途 |
| --- | --- | --- | --- |
| `sensemind_device` | HTTP、解析、错误、日志（必用） | `ipaddress` | IP/CIDR 处理 |
| `json` | 手工解析/构造响应 | `base64` | 口令编码、Token |
| `hashlib` | 签名（md5/sha256） | `hmac` | HMAC 签名 |
| `time` | 时间戳、`sleep` | `datetime` | 时间格式 |
| `re` | 文本提取 | `urllib` | URL 编码（`urllib.parse`） |
| `contextlib` | `@contextmanager` 管会话 | `typing` | 类型注解 |
| `dataclasses` | 内部数据结构 | `enum` | 常量枚举 |
| `collections` | 有序字典等 | `math` | 计算 |
| `random` | 随机数 | `secrets` | 强随机 |
| `string` | 字符集常量 | `struct` / `textwrap` / `uuid` | 打包、文本、ID |
| `logging` | 仅在需要自定义 handler 时（一般用 `logger()`） | `http` | HTTP 状态码常量 |

**不在名单里的一律拒绝**，包括：`httpx`、`requests`、`os`、`sys`、`subprocess`、`socket`、`ssl`、`ctypes`、`importlib`、`pickle`、`shutil`、`multiprocessing`、`__future__`。

几个新手最常踩的：

- **`import httpx` 会被拒**。只用 `http_client()` / `send()`，不要自己建客户端，也不要写 `-> httpx.Client` 这种注解。
- **`from __future__ import annotations` 会被拒**。想用新式注解就直接写字符串注解或 `typing.Optional`。
- **不要 `import os` 读环境变量**。凭据一律来自 `cfg`，平台已解密后传给你。

内置脚本不受这条限制（它们随镜像发布、经过代码审阅），所以**照抄内置脚本的导入语句可能过不了上传检查**。以本节为准。

### 2.3 禁止的内建与语法

静态检查另外禁用了下列符号，命中即拒绝上传：

| 类别 | 清单 |
| --- | --- |
| 动态执行 | `eval`、`exec`、`compile`、`__import__`、`breakpoint` |
| 文件 | `open` |
| 反射/自省 | `getattr`、`setattr`、`delattr`、`globals`、`locals`、`vars`、`dir`、`input` |
| 双下划线属性 | 任何 `xxx.__yyy__` 形式的属性访问 |
| 特殊名字 | `__builtins__`、`__loader__`、`__spec__` |

这带来三个反直觉的限制，写之前就要绕开：

1. **不能用 `getattr(obj, "k", None)`** —— 用 `obj.get("k")` 或 `if "k" in obj` 代替（响应体基本都是 dict）。
2. **不能用 `type(x).__name__`、`obj.__class__`、`obj.__dict__`** —— 需要类型判断就用 `isinstance`，需要导出字段就显式写。
3. **不能用 `super().__init__()`** —— `.__init__` 属于双下划线属性，会被拒。脚本里不要用类继承，用普通函数 + dict 就够了。

可以放心用的：`isinstance`、`len`、`sorted`、`dict.get`、f-string、`@contextmanager`、`@dataclass`、`try/except/finally`、`with`。

### 2.4 sensemind_device 全部 API

脚本只依赖这一个模块（`alert-responder/sensemind_device/`）。以下是全部可用接口，**没有别的**（不要指望里面有数据库、任务、白名单相关的能力，那些都在平台侧）。

#### `http_client(cfg, *, cookies=None, headers=None, timeout=None) -> httpx.Client`

按 `cfg["base_url"]` 建客户端，并统一消费平台字段：

```python
client = http_client(cfg, headers={"Content-Type": "application/json; charset=UTF-8"})
```

| 行为 | 说明 |
| --- | --- |
| `base_url` | 取 `cfg["base_url"]`，**所以地址字段必须叫 `base_url`**，否则取不到会抛 `config_invalid` |
| 超时 | 取 `timeout_seconds`（默认 10 秒），可用 `timeout=` 覆盖 |
| 证书 | 按 `verify_tls` / `ca_cert_pem` 决定，**不要在脚本里写死 `verify=False`** |
| 重定向 | `follow_redirects=False`，登录跳转不会被自动跟随 |
| 生命周期 | 返回的 client **必须 `close()`**，否则连接泄漏 |

#### `send(client, method, url, **kwargs) -> httpx.Response`

```python
response = send(client, "POST", "/api/login", json={"name": user, "password": pwd})
```

只做一件事：把 `httpx.TimeoutException` / `httpx.HTTPError` 统一收敛成 `DeviceError(code="timeout"|"network", retryable=True)`。**它不判断 HTTP 状态码**，2xx/4xx/5xx 都会原样返回，判定要你自己写（见 5.1）。

`**kwargs` 原样交给 `httpx.Client.request()`，厂商常见的几种报文形态都用它表达：

| 要发的形态 | 写法 |
| --- | --- |
| JSON | `send(client, "POST", "/api/blacklist", json={"ip": ip})` |
| 表单（`application/x-www-form-urlencoded`） | `send(client, "POST", "/login", data={"username": u, "password": p})` |
| 同名键重复（`cmd=a&cmd=b`） | `send(client, "POST", "/x", data=[("cmd", "a"), ("cmd", "b")])` |
| multipart 上传（`multipart/form-data`） | `send(client, "POST", "/upload", files={"file": ("a.conf", b"...", "text/plain")})` |
| 查询串 | `send(client, "GET", "/api/list", params={"ip": ip})` |
| Cookie | `http_client(cfg, cookies={"SESSION": token})` |

只被捕获的是超时和网络异常；其余异常（URL 拼了中文/空格、序列化失败等）会以原类型冒泡，联动日志里记成该异常类名。

#### `status_error(response, *, message="") -> DeviceError`

HTTP 层失败分类器：5xx / 429 → `retryable=True`，其余 4xx → `retryable=False`。

```python
if response.status_code >= 400:
    raise status_error(response, message="添加黑名单被拒绝")
```

#### `json_body(response, *, code="bad_response") -> dict`

取响应 JSON。非法 JSON、或顶层不是对象（比如是数组）都会抛 `DeviceError`。顶层是数组时用 `response.json()` 自己处理。

#### `json_after_token(response, *, code="bad_response") -> (token|None, dict)`

有些设备的 WebUI 接口把会话 token 塞在 JSON 前面（形如 `?[TOKEN}?{"result":true}`），必须先切前缀再解析：

```python
token, payload = json_after_token(response)
if token:
    session_token = token      # 下一次请求要带上
```

#### `split_token_prefix(text) -> (token|None, str)`

手工切前缀，逻辑同上，但接受任意字符串（比如你已经 `response.text` 处理过）。

#### `check_ip(value) -> str`

校验并规范化单个 IP：`" 10.0.0.01 "` → `"10.0.0.1"`；`"::1"` → `"::1"`；非法抛 `DeviceError("invalid_ip")`。**不接受 CIDR**（`10.0.0.0/24` 会被拒）。

#### `check_network(value) -> str`

校验并规范化 CIDR，用于白名单类接口：`10.0.0.5/24` → `10.0.0.0/24`（不严格模式）。非法输入抛 `DeviceError("invalid_ip")` 或 `DeviceError("invalid_cidr")`。

#### `aes_cbc_zero_base64(text, key, iv) -> str`

国产业务常见的「AES-CBC + 零填充 + 标准 base64」口令加密。免去脚本依赖 `cryptography`（它不在白名单里）：

```python
encrypted = aes_cbc_zero_base64(password, "ngfwrestapilogin", "ngfwrestapilogin")
```

要求：key 长度 16/24/32 字节，iv 16 字节；明文按 `\x00` 补齐到 16 的整数倍。key/iv 长度不对时抛的是 `ValueError`（不是 `DeviceError`），联动日志里会记成失败码 `ValueError`——尺寸常量写死，别用运行时拼接的字符串。**PKCS7 填充、URL-safe base64、hex 输出都不在这个函数的能力范围**——遇到这类算法，用 `hashlib`/`base64` 自己实现。

#### `logger(name) -> logging.Logger`

```python
log = logger("vendor_x")     # 日志归到 sensemind_device.vendor_x
log.info("已加入黑名单：%s", target)
```

**不要用 `print`**：容器日志里分不清是哪个设备脚本，也无法按级别过滤。

#### `mask(value)` / `mask_config(cfg)`

脱敏工具，仅供日志：

```python
log.debug("配置：%s", mask_config(cfg))     # password/token/secret/key 类字段自动变 ***
```

#### `DeviceError(code, message="", retryable=False, *, status=None)`

见 3.4。

#### `ProbeResult(ok, message="", detail={})`

连接测试的返回结构，`message` 会直接显示在页面上。

#### `API_VERSION = 1`

平台接口版本。见 3.1。

#### `set_transport_factory(factory)`

仅平台自检使用（注入 `httpx.MockTransport`）。**脚本里不要调用**。

---

## 三、脚本规范

ABI v1 是什么：这里指「平台 ↔ 设备脚本」之间的调用约定——脚本要暴露哪些模块级常量、哪些函数、参数与返回结构是什么、错误怎么表达。`v1` 对应当前版本 `sensemind_device.API_VERSION = 1`；将来若做不兼容变更（例如要求 `block` 支持批量下发），平台会递增版本，脚本若自己声明了 `API_VERSION` 就必须与平台一致，否则拒绝加载。

平台在启动时扫描脚本并逐个校验；**任何不合规直接加载失败并记 ERROR 日志，不静默跳过**（上传场景是当场返回 400，不会落盘）。

### 3.1 文件命名与 MANIFEST

文件名（不含 `.py`）= `MANIFEST["key"]`，不一致即加载失败。文件名规则：`^[a-z][a-z0-9_]{0,63}$`，即小写字母开头，只含小写字母/数字/下划线。

```python
MANIFEST = {
    "key": "vendor_x",                  # 必须与文件名一致，全局唯一
    "display_name": "厂商 X 防火墙",     # 前端下拉与列表显示；全局唯一，与其他设备类型重复会拒绝上传
    "schema_version": 1,                # >=1 的整数；同一 key 的字段结构变更时递增
    "order": 60,                        # 可选，下拉展示顺序（小的在前），不写按 100 靠后
    "config_schema": [ ... ],           # 非空列表，见 3.2
    "capabilities": {"ipv6": False},    # 只有 ipv6 需要显式声明
}
```

| 键 | 必需 | 说明 |
| --- | --- | --- |
| `key` | 是 | 与文件名一致，全局唯一，改了会导致加载失败 |
| `display_name` | 是 | 展示名，**全局唯一**（内置 + 自定义一起算）。重名会让下拉出现两个无法区分的选项，所以上传时就拒绝 |
| `schema_version` | 是 | 字段结构版本，>=1 的整数。改了 `config_schema` 就递增 |
| `config_schema` | 是 | 非空列表，见 3.2 |
| `order` | 否 | 非负整数，下拉排序用，小的在前；**建议显式填**，否则顺序随文件名漂移 |
| `capabilities` | 否 | 目前只有 `ipv6` 需要声明，默认 `false` |

可选模块级常量 `API_VERSION`：不写视为与平台一致；写了就必须等于 `1`。**接口不兼容变更时平台递增该值，旧脚本会被拒绝加载**——这是有意的，避免等到封堵时才炸。

`MANIFEST` 里多写的键（`author`、`version` 之类）既不读取也不报错，别指望它承载语义；反过来，`key`、`display_name`、`schema_version`、`config_schema` 缺任何一项都是加载失败。

### 3.2 配置字段描述符

```python
{
    "name": "base_url",                  # 必需，cfg 里的键名
    "label": "管理地址",                  # 必需，表单标签与错误提示用
    "type": "url",                       # 必需，见下表
    "required": True,                    # 必填（敏感字段编辑时留空不算缺失）
    "default": "https://10.0.0.1:8443",  # 新建时的初始值
    "placeholder": "https://10.0.0.1:8443",
    "help": "含协议，端口按设备实际填写",   # 表单项下方灰色说明
    "secret": True,                      # 敏感字段：加密落库、读取不回显
    "choices": ["A", "B"],               # type=select 时必需
    "depends_on": {"mode": "api"},       # 单层条件显隐：mode 的值等于 api 时才显示
}
```

| `type` | 渲染 | 说明 |
| --- | --- | --- |
| `text` | 单行输入 | |
| `password` | 密码框 | 配合 `secret: True` |
| `url` | 单行输入 | 语义标记，平台不额外校验格式 |
| `int` | 数字框 | 平台强转整数，失败报 400 |
| `bool` | 开关 | `"1"/"true"/"yes"/"on"` 视为真 |
| `select` | 下拉 | **必须给 `choices`**，值不在其中报 400 |
| `textarea` | 多行 | 适合证书 PEM |

三条硬规则：

1. **保留字段名不得声明**：`timeout_seconds`、`verify_tls`、`ca_cert_pem`、`max_concurrency`。这四项由页面「高级选项」统一渲染、由 `http_client()` 统一消费，脚本声明即加载失败。
2. **字段名不能重复**，否则加载失败。
3. `depends_on` 只支持单层对象，不支持嵌套或多值。

`default` 只在页面「添加设备」时预填表单，平台侧既不校验也不回填；`placeholder`、`help` 纯展示、不参与任何判断。`required` 由平台在校验保存时使用——敏感字段（`secret: True`）编辑时留空视为「沿用旧值」，不算缺失。

地址字段请统一叫 **`base_url`**——`http_client(cfg)` 只认这个名字。

### 3.3 函数约定

必需（缺一即加载失败）：

```python
def block(ip: str, cfg: dict, ctx=None) -> None:
    """封堵单个 IP；失败必须抛 DeviceError，禁止静默返回。"""

def unblock(ip: str, cfg: dict, ctx=None) -> None:
    """解除封堵；IP 本来不在黑名单时应视为成功（幂等）。"""
```

可选（有则自动置对应能力位）：

```python
def test_connection(cfg: dict) -> ProbeResult:
    """连接测试，给页面「测试连接」回显。"""

def list_blocked(cfg: dict) -> list[str]:
    """返回设备当前封堵的 IP 列表。只用于给页面标能力位，平台不会调用它做封堵前回读。
    分页行为未经真机核验时不要实现。"""
```

`ctx` 的默认值**不是可选的**：平台按 `block(ip, cfg)` 两个位置参数调用，`ctx` 恒为 `None`。写成 `def block(ip, cfg, ctx)`（没有默认值）能通过上传校验，但一调用就 `TypeError`——接口照样返回 200，只在联动日志里记一条 `failed`，很容易漏看。所以：

- 两个必需函数的第三个参数一律写 `ctx=None`（保留这个形参只为签名兼容，平台不会传值）；
- 登录与退登都写在 `block` / `unblock` 内部，几次请求复用同一个 `client`（见第四节的写法）；
- **不要实现 `setup()` / `teardown()`**：平台不调用它们，写了也不会执行。

能力位由实现反推，不在清单里声明，避免「声明了但函数没写」：

- `capabilities.test` = 是否存在 `test_connection`
- `capabilities.list_blocked` = 是否存在 `list_blocked`
- `capabilities.ipv6` = `MANIFEST["capabilities"]["ipv6"]`

调用约定：

- **单 IP 粒度**。批量由平台循环、逐 IP 落封堵记录，脚本不要自己拼批量请求。
- `cfg` 由平台构造并解密后传入，**脚本不读环境变量、不自己存凭据**。
- `block` / `unblock` 的返回值被忽略（写 `-> None` 即可）：成功就正常返回，失败必须抛异常，**不要靠 return 文本表达结果**。
- `test_connection` 请走「最小验证」：只验证登录/握手成功，不要顺便跑一次真实封堵。

### 3.4 错误与 retryable

```python
from sensemind_device import DeviceError

raise DeviceError("vendor_rejected", f"添加黑名单失败：{msg}", retryable=False, status=400)
```

| 字段 | 说明 |
| --- | --- |
| `code` | 稳定的短标识，用于排错统计。常用值：`config_invalid`、`invalid_ip`、`timeout`、`network`、`http_error`、`login_failed`、`login_no_token`、`bad_response`、`vendor_rejected`、`block_not_effective`、`unblock_not_effective` |
| `message` | 人可读原因，会显示在联动日志里。**设备返回了原因就带上**，别只写"失败" |
| `retryable` | **只有网络中断、超时、5xx、429 才为 `True`**。厂商业务码拒绝、4xx、凭据错误一律 `False`——否则重试只会重复打设备 |
| `status` | HTTP 状态码，可选 |

`ProbeResult(ok=False, message="...")` 用于连接测试回显；连接测试失败也可以直接 `raise DeviceError`，平台会转成 `{ok: false, code, retryable}`。

平台不会按 `retryable` 自动重试：这个标记只写进联动日志、并随「测试连接」回显，供人工判断或外部调度参考。**但它仍要标对**——标错的直接后果是排障时判断反向（把明确的业务拒绝当偶发故障去反复重试），而不是平台自己重放。

关键点：**失败必须抛异常，不能 `return`**。静默返回会让平台把失败的封堵记成成功，还会把原告警标记 `blocked=true`，之后没人知道流量其实没被拦住。

---

## 四、完整模板

与页面「下载示例脚本」拿到的是同一份内容（`example_vendor.py`）。复制后改文件名与 `MANIFEST["key"]` 即可跑通。

```python
"""示例设备脚本：把 IP 写入厂商设备的黑名单表。

使用步骤
1. 下载本文件，改名为 `<vendor>_device.py`，并把 MANIFEST["key"] 改成同名（去掉 `.py`）。
2. 按厂商接口改 `BLACKLIST_PATH` 以及 block/unblock 里的请求体字段。
3. 通过「添加联动设备 → 上传设备脚本」上传，上传后设备类型下拉里会多出 MANIFEST["display_name"]。

约束
- 文件名（去掉 .py）必须与 MANIFEST["key"] 完全一致，且只能是小写字母开头的字母/数字/下划线。
- 必须实现 `block(ip, cfg, ctx=None)` 与 `unblock(ip, cfg, ctx=None)`；`test_connection` 与 `list_blocked` 可选。
- 网络请求统一走 `sensemind_device` 提供的 `http_client` / `send`，超时、证书校验由平台配置统一管理。
- 上传的脚本会被平台导入执行，仅管理员可上传，且只能导入第二节白名单里的模块。
"""

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
    "key": "example_vendor",
    "display_name": "示例厂商防火墙",
    "schema_version": 1,
    "order": 90,
    "config_schema": [
        {
            "name": "base_url",
            "label": "管理地址",
            "type": "url",
            "required": True,
            "placeholder": "https://10.0.0.1:8443",
            "help": "含协议与端口，例如 https://10.0.0.1:8443",
        },
        {
            "name": "username",
            "label": "用户名",
            "type": "text",
            "required": True,
        },
        {
            "name": "password",
            "label": "密码",
            "type": "password",
            "required": True,
            "secret": True,
            "help": "保存后前端不再回显，编辑时留空表示沿用旧值",
        },
    ],
    "capabilities": {"ipv6": False},
}

log = logger("example_vendor")

BLACKLIST_PATH = "/api/blacklist"


def _client(cfg: dict):
    username = str(cfg.get("username") or "").strip()
    password = cfg.get("password") or ""
    if not username or not password:
        raise DeviceError("config_invalid", "缺少用户名或密码", retryable=False)
    client = http_client(cfg, headers={"Content-Type": "application/json"})
    # 设备要求先登录换 token 时：在这里发登录请求，成功后把 token 写进 client.headers
    return client


def test_connection(cfg: dict) -> ProbeResult:
    client = _client(cfg)
    try:
        response = send(client, "GET", BLACKLIST_PATH)
    finally:
        client.close()
    if response.status_code >= 400:
        raise status_error(response, message="黑名单接口不可用")
    return ProbeResult(ok=True, message="连接正常，黑名单接口可读")


def block(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    client = _client(cfg)
    try:
        response = send(client, "POST", BLACKLIST_PATH, json={"ip": target, "action": "add"})
        if response.status_code >= 400:
            raise status_error(response, message="添加黑名单失败")
        payload = json_body(response)
        if str(payload.get("code")) != "0":
            raise DeviceError(
                "vendor_rejected",
                f"添加黑名单失败：{payload.get('message') or payload.get('code')}",
                retryable=False,
            )
        log.info("已加入黑名单：%s", target)
    finally:
        client.close()


def unblock(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    client = _client(cfg)
    try:
        response = send(client, "POST", BLACKLIST_PATH, json={"ip": target, "action": "remove"})
        if response.status_code >= 400:
            raise status_error(response, message="移除黑名单失败")
        payload = json_body(response)
        if str(payload.get("code")) != "0":
            raise DeviceError(
                "vendor_rejected",
                f"移除黑名单失败：{payload.get('message') or payload.get('code')}",
                retryable=False,
            )
        log.info("已移出黑名单：%s", target)
    finally:
        client.close()


def list_blocked(cfg: dict) -> list:
    """可选：返回设备侧黑名单 IP 列表。不实现则平台标记该设备类型不支持回读。"""
    client = _client(cfg)
    try:
        response = send(client, "GET", BLACKLIST_PATH)
    finally:
        client.close()
    if response.status_code >= 400:
        raise status_error(response, message="读取黑名单失败")
    payload = json_body(response)
    items = payload.get("data") or []
    if not isinstance(items, list):
        return []
    ips = []
    for item in items:
        value = item.get("ip") if isinstance(item, dict) else item
        if value:
            ips.append(str(value))
    return sorted(ips)
```

一次 `block` 里往往要连着发好几个请求（登录 → 查询 → 添加 → 回查 → 退登）。**不要实现 `setup()` / `teardown()`**：平台调用的是 `block(ip, cfg)`，不会传 `ctx` 进来，这两个函数永远不会被执行。正确做法是在 `block` 内部登录一次，几步请求复用同一个 `client`，`finally` 里退登并 `close()`：

```python
def _login(cfg: dict):
    """登录后返回一个已带凭据的 client；由调用方负责 close()。"""
    client = http_client(cfg, headers={"Content-Type": "application/json"})
    try:
        response = send(client, "POST", "/login", json={
            "username": cfg.get("username"), "password": cfg.get("password"),
        })
        if response.status_code >= 400:
            raise status_error(response, message="登录请求被拒绝")
        token = (json_body(response).get("data") or {}).get("token")
        if not token:
            raise DeviceError("login_no_token", "登录成功但未返回 token", retryable=False)
    except BaseException:
        client.close()          # 登录在任何一个环节失败都要关掉客户端
        raise
    client.headers["X-Token"] = token
    return client


def block(ip: str, cfg: dict, ctx=None) -> None:
    target = check_ip(ip)
    client = _login(cfg)
    try:
        if _exists(client, target):            # 同一个 client 连着发：先查
            log.info("%s 已在黑名单，跳过", target)
            return
        _add(client, target)                   # 再添加
        if not _exists(client, target):        # 最后回查
            raise DeviceError("block_not_effective", "写入成功但回查不到条目", retryable=True)
    finally:
        try:
            send(client, "POST", "/logout")
        except Exception:
            log.warning("退登失败，忽略")       # 退登失败不能推翻已成功的封堵
        client.close()
```

---

## 五、实战经验与常见坑

以下是落地过多个厂商设备后总结的通用规律，**按踩坑概率排序**。写脚本前扫一遍能省掉大量真机调试。

### 5.1 「HTTP 200」不等于成功

绝大多数国产设备在业务失败时依然返回 **200**，真正的结果在响应体的 `code` / `error_code` / `status` / `result` 里。

```python
if response.status_code >= 400:
    raise status_error(response, message="添加黑名单失败")   # 只管传输层
payload = json_body(response)
if payload.get("code") not in (0, "0", None):               # 业务层要自己判
    raise DeviceError("vendor_rejected", f"添加失败：{payload.get('message')}", retryable=False)
```

反过来也要注意：**有些设备鉴权失败也返回 200**，body 里是登录页 HTML 或 `code: "not_login"`。这种「假成功」最难查——表现是封堵记录显示成功，设备侧却没有条目。出现这种情况，优先怀疑没判业务码。

### 5.2 业务码的类型不统一

同一个字段在同一个设备上可能是 `2000`、`"2000"`、`True`、`"success"`，甚至不同固件版本不一致。**用字符串比较兜住两边**：

```python
if str(payload.get("status")) != "2000":
    raise DeviceError("vendor_rejected", ...)
```

成功判据如果是「多个信号任一成立」，就都写上，别只认一种：

```python
if payload.get("code") in (0, "0") or payload.get("message") == "成功":
    return
```

### 5.3 幂等：封堵前先查，解封不存在算成功

平台会重试，人工也会重复点。`block` 必须能承受"这个 IP 已经在黑名单里"：

```python
if _already_blocked(client, cfg, target):
    log.info("IP 已在黑名单，跳过：%s", target)
    return
```

`unblock` 同理，目标不存在要当成功：

```python
if not _already_blocked(client, cfg, target):
    log.info("IP 不在黑名单，跳过：%s", target)
    return
```

不做幂等的直接后果：设备返回「条目已存在」→ 被当成失败 → 联动日志一片红 → 运维开始忽略真实故障。

### 5.4 设备说成功，但其实没生效——写完要回查

有些设备（尤其是「整体覆盖」型接口）返回成功却没有真正落库，或者落库有延迟。**处置后再查一次**，是最值得加的一段代码：

```python
def _verify(client, cfg, ip: str, expect_blocked: bool):
    """True=与预期一致，False=不一致，None=查询本身出错（不改结论）"""
    for attempt in (1, 2):
        try:
            actual = _query_blocked(client, cfg, ip)
        except Exception as exc:
            log.warning("复查 %s 状态失败：%s", ip, exc)
            return None          # 查询失败不改变处置结论，避免与设备实际状态相反
        if actual == expect_blocked:
            return True
        time.sleep(0.4)
    return False


if _verify(client, cfg, target, expect_blocked=True) is False:
    raise DeviceError("block_not_effective", "设备返回成功，但复查未在名单中查到该 IP", retryable=True)
```

三条原则：

1. **回查异常不能判失败**。网络抖动导致查不到，不代表封堵没成功；判失败会让平台记 `failed`、不写 `blocked=true`，与设备实际状态相反。
2. **明确不符要判失败**，`retryable=True`（可重试）。
3. 回查间隔给 0.3~0.5 秒、最多 2 次就够，别写成轮询。

### 5.5 模糊查询不等于精确匹配

带搜索参数的查询接口经常是**模糊匹配**：搜 `10.0.0.1` 会同时返回 `10.0.0.10`、`10.0.0.100`、`10.0.0.1-10.0.0.5` 这类地址段。

拿到结果后必须**逐项精确比对**，不能只看"有返回就说明存在"：

```python
rows = [r for r in items if str(r.get("ip_start")) == ip and str(r.get("ip_end")) == ip]
if not rows:
    # 没有精确匹配
```

同一个坑还有反面：`search` 只用来缩小范围，有的设备会**忽略**它返回全量，有的只返回前 N 条。判定前先看 `total`，必要时退化成 `size=-1` / `limit=0` 取全量再比对。

### 5.6 删除接口「返回成功但不生效」

有设备的删除接口只要参数能对上就返回 `code=0`，但实际没删——常见原因是它按某个具体字段（起止地址、条目 id）匹配，而你传的是另一个字段（名称）。

**判断依据只能是回查**（见 5.4），或者严格按厂商文档给全匹配字段。不要相信删除接口的返回码。

### 5.7 分页：列表能力要么做对，要么不做

`list_blocked` 是可选的。**分页行为没在真机核验过就别实现**——平台会把它的结果当真，接错了比不接更糟。

要实现的写法：

```python
page, total_pages = 0, 1
while page < total_pages:
    response = send(client, "GET", path, params={"type": "BLACK", "_length": 200, "_start": page * 200})
    payload = json_body(response)
    data = payload.get("data") or {}
    total_pages = int(data.get("totalPages") or 1)
    items += data.get("items") or []
    log.info("第 %s 页取到 %s 条（totalPages=%s）", page + 1, len(data.get("items") or []), total_pages)
    page += 1
```

翻页死循环的防护：`totalPages` 解析失败就当 1，并且给 `page` 一个上限。

### 5.8 读-改-写：整体覆盖型接口有并发风险

地址簿 / 对象组这类接口通常是「PUT 整个组」，而不是「加一个成员」。两个请求并发时后写会覆盖先写，表现为**明明返回成功，成员却丢了**。

处理办法：写完立即回读；不符则重新「读→改→写」一次，最多 2 次；仍不符抛 `block_not_effective`。

### 5.9 判断「资源不存在」要看语义码，别匹配中文文案

成对出现的错误码比文字稳定得多。中文文案会随固件语言包、版本变化，也可能被本地化改掉：

```python
NOT_FOUND_CODE = 1004        # 设备的「资源不存在」语义码

def _is_not_found(payload: dict) -> bool:
    try:
        return int(payload.get("code")) == NOT_FOUND_CODE
    except (TypeError, ValueError):
        return False
```

文案（`"不存在" in response.text`）只能作为最后兜底，且要放在语义码判断之后。反过来，也别把 `404` 当成唯一判据——很多设备的"不存在"是 200 + 业务码。

### 5.10 会话与 token 的生命周期

三类形态，先确认设备是哪一类，别猜：

| 形态 | 特征 | 做法 |
| --- | --- | --- |
| 登录换 token | 登录接口返回 token/会话 id | token 放 header 或 cookie，后续请求带上 |
| 静态 Token | 设备页面生成长期 Token | 每个请求带 `Authorization: <token>`，不登录不换会话 |
| Cookie 会话 | 登录后下发 Set-Cookie | 用 `http_client(cfg)` 的 cookie jar 自动承接，注意别新建 client |

token 放哪里要按设备来，两种都见过：

```python
client.headers["X-Auth-Token"] = token                 # header
client.cookies.set("token", token)                     # cookie
```

**会话过期要自重登一次**：长任务里 token 可能中途失效，收到 401/403 或返回体里的 `loginError_*` 类错误时，重新登录并把当前请求重试一次，仍失败才报错。别把 401 直接抛成 `retryable=False` 让整批任务失败。

退登要 `try/except` 包住再 `close()`：**退登失败不能影响已经成功的封堵结论**。

```python
def _logout(client, cfg) -> None:
    try:
        send(client, "POST", "/logout")
    except Exception:
        log.warning("退出登录失败，忽略")
    finally:
        client.close()
```

### 5.11 响应不是纯 JSON

除了标准的 `{"code": 0, "data": {...}}`，实际见过这些形态：

| 形态 | 处理 |
| --- | --- |
| JSON 前带 token 前缀 `?[TOKEN}?{...}` | `json_after_token(response)` |
| 整个 body 是 base64 编码的 JSON | `json.loads(base64.b64decode(response.text))` |
| 成功返回 HTML/空 body，失败才返回 JSON | 判 `response.text` 是否为空，空按成功但要配合回查 |
| 顶层是数组，元素是 `{"head": {...}, "body": {...}}` | `response.json()` 后用 `[0]` 取，别用 `json_body` |

### 5.12 登录口令要加密 / 请求要签名

不少设备不接受明文口令，或者要求请求带签名。两类常见算法：

| 类型 | 做法 |
| --- | --- |
| 口令加密 | 优先用 `aes_cbc_zero_base64(text, key, iv)`；PKCS7、URL-safe base64、hex 输出用 `base64` + `hashlib` 自己实现 |
| 请求签名 | `md5(secret + token + url + body)` 这类，用 `hashlib.md5(...).hexdigest()`；HMAC 用 `hmac.new(key, msg, hashlib.sha256).hexdigest()` |

注意两点：

- **签名用的串要和厂商给的一模一样**：分隔符、参数顺序、大小写、是否 URL 编码、body 是 JSON 字符串还是 dict 的 `str()` 表示——差一个字符就通不过，且设备通常只回"签名错误"。
- **每一步都要重新算**：有的设备每次响应都会换 token（`?[新token}?` 前缀），下一次请求必须用**最新的**，用旧的会失败。这类 token 别缓存到 `cfg` 里跨请求复用。

### 5.13 设备侧的前置条件：接口成功，流量照样通

这条不属于脚本问题，但排查时最容易漏。**封堵写进"对象组"不等于生效**：

- 地址簿/对象组只是容器，**必须被安全策略引用**（源或目的）才会真正拦流量；
- 黑名单有**容量上限**（某些设备地址黑名单上限 1000 条），超了会静默丢或报错；
- 名单可能是**独立入口**，与策略里的阻断表不是同一张表。

所以交付前一定要在设备侧真实流量上验一次，而不是只看接口返回 200。

另一类前置条件在账号本身：

| 项 | 要求 |
| --- | --- |
| 权限 | 只授予「地址黑名单 / 地址对象」读写权限；只读角色会在封堵时才报错 |
| 专用账号 | 建一个专用账号给平台，别复用默认 `admin`：权限最小化、审计可分、被锁定不影响人工登录 |
| 登录来源限制 | 设备若限制了登录源地址，须把 `alert-responder` 容器的出口 IP（或 Docker 网桥网段）加白，否则登录直接被拒 |
| 双因素 / 验证码 | 必须对该账号关闭，否则拿不到可用会话 |
| 密码策略 | 关闭「首次登录强制改密」与过期提醒 |
| 证书 | 管理口多为自签证书，页面「高级选项」里保持「校验证书」关闭（默认已关）；用内部 CA 时可开启并填 `ca_cert_pem` |

### 5.14 IP 形态与 IPv6

- 一律先 `target = check_ip(ip)`，平台传进来的 IP 已经是规范形式，但脚本自己去查设备时也要用规范形式，否则字符串比对会失败（`10.0.0.1` vs `10.0.0.01`）。
- `check_ip` **不接受 CIDR**，白名单类接口才用 `check_network`。
- IPv6 只有在设备与脚本两侧都支持时才声明 `capabilities.ipv6 = true`；没在真机验证过就保持 `false`（未验证就声明会让平台把 IPv6 告警推给一个接不住的设备）。
- 主机对象/掩码：IPv4 用 `netmask=32`，写死 32 的脚本天然不支持 IPv6，这也是多数设备类型声明 `ipv6=False` 的原因。

### 5.15 日志与脱敏

```python
log = logger("vendor_x")
log.info("已加入黑名单：%s", target)
log.debug("配置：%s", mask_config(cfg))
```

- 用 `%s` 惰性格式化，别用 f-string 拼进日志（低级别日志也会先算一遍字符串）。
- **不要打印明文密码/token**。需要打整个配置就用 `mask_config()`。
- 关键节点留痕：登录成功、条目已存在跳过、写入成功、回查结果。这几行在真机调试时价值最大。
- 不要用 `print`：容器日志里没有设备上下文，也没法按级别过滤。

### 5.16 其它零散但会卡住的点

| 现象 | 处理 |
| --- | --- |
| 请求总是 400 | `Content-Type` 没带或带错；有的设备只收 `application/x-www-form-urlencoded`，有的只收 `text/plain` 承载 JSON |
| 请求 415 | 内容类型与设备预期不符，试着换 `text/plain;charset=UTF-8` 重发同一份 JSON |
| 中文乱码/签名错 | 显式 `ensure_ascii=False` 或显式 `json.dumps(..., separators=(",", ":"))`，别依赖默认序列化 |
| 时间戳被拒 | 设备要本地时间或固定时区，用 `datetime` 显式按设备要求格式化 |
| 登录总失败但网页能登 | 大概率是验证码/双因素没关，或走了需要 `Referer`/`User-Agent` 的 WebUI 接口 |
| 首次调用成功，第二次 401 | 会话被设备主动回收（单会话设备），要么每次操作重登，要么别并发 |
| 参数名大小写不符 | 设备接口对字段大小写敏感，按文档逐字抄，不要"顺手规范化" |
| 同厂商不同型号/固件返回字段不一致 | 例：一台回 `urlType: "ip"`，另一台不回 `urlType` 而用 `domain: 0` 表示 IP 对象。判定条件必须允许字段缺失（缺 `urlType` 时看 `domain`），否则「已封禁」被判成「不在名单」——解封被跳过、封堵重复下发 |

---

## 六、上传、生效与安全边界

### 6.1 页面操作

内置设备类型覆盖不到的厂商，可自行编写设备脚本并从页面上传，**不需要改平台代码，也不需要重启服务**。

1. 侧栏 **联动外发 → 联动处置** → 「添加联动设备」。
2. 点「下载示例脚本」，按第四节改成自己的脚本。
3. 点「上传设备脚本」选择该文件。上传成功后设备类型下拉自动刷新并选中新设备类型。
4. 若提示「已存在同名脚本」，确认覆盖后替换生效；已使用该设备类型的设备立即改用新脚本，无需重启。
5. 若提示「同名设备已存在」，说明 `MANIFEST["display_name"]` 与已有设备类型（内置或已上传）重复。前端下拉只显示 display_name，同名会出现两个无法区分的选项，因此平台在上传时直接拒绝；改成本设备类型独有的名称后重新上传即可。

脚本管理：弹窗里「自定义设备脚本」区域可查看已上传的脚本列表（设备类型、文件名、上传时间、上传人）并一键删除。

### 6.2 上传时的校验

上传的脚本会被平台**导入并执行**（脚本即代码），因此只有管理员可上传，且校验分三层——任一层不通过都不会落盘：

| 层 | 规则 |
| --- | --- |
| 文件 | 必须是 `.py`；文件名（去扩展名）即 `MANIFEST["key"]`，需匹配 `^[a-z][a-z0-9_]{0,63}$`；体积 ≤ 256 KB；只接受 UTF-8 文本，含 NUL 字节直接拒绝 |
| 静态检查 | `ast.parse` 校验语法；`import` 只能命中 2.2 的白名单；禁用 2.3 列出的内建与双下划线属性 |
| 清单与签名 | 与内置脚本同一套校验：`MANIFEST` 必填键、`config_schema` 合法性、`display_name` 全局唯一、`block`/`unblock` 必须存在、`API_VERSION` 一致 |

落盘流程：脚本先写进 `devices/custom/.upload/<随机目录>/` 完成全部校验，通过后才移到 `devices/custom/` 并触发热加载；校验失败则删掉临时目录，已有脚本不受影响。

**上传前逐条自检**（这一层的错最容易在上传后才暴露）：

1. 文件名（去掉 `.py`）与 `MANIFEST["key"]` 完全一致，且只含小写字母/数字/下划线、小写字母开头；大写、中文、连字符都会被拒。
2. `display_name` 与已有设备类型（内置 + 已上传）不重名，重名直接拒绝上传。
3. `import` 只出现 2.2 那 24 个模块：没有 `httpx`、`requests`、`os`、`sys`、`__future__`；连 `-> httpx.Client` 这种注解也不要写。
4. 没有 `eval`/`exec`/`compile`/`open`/`getattr`/`setattr`/`globals`/`locals`/`vars`/`dir`，也没有任何 `.__xxx__` 形式的属性。
5. `block`、`unblock` 存在，签名是 `(ip, cfg, ctx=None)`——**`ctx` 必须有默认值**，平台只传两个位置参数。
6. 地址字段叫 `base_url`（`http_client()` 只认这个键），`type` 用 `url`。
7. 每处 `http_client()` 都配 `try/finally: client.close()`，异常路径也不漏。
8. 失败一律 `raise DeviceError(...)`，消息里带上设备返回的原因；厂商业务拒绝用 `vendor_rejected` + `retryable=False`。
9. 判成功看设备业务码，不能只看 HTTP 200（见 5.1、5.2）。
10. 封堵前先查已存在、解封不存在算成功（幂等，见 5.3）；接口支持回读时补一次回查（见 5.4）。

### 6.3 覆盖、删除与已保存设备的关系

| 操作 | 结果 |
| --- | --- |
| 同 key 覆盖上传 | 使用该设备类型的设备**立即**改用新实现，配置与凭据不变；若字段结构变了（`schema_version` 递增），需进设备页重新保存一次配置 |
| 删除自定义脚本 | **只删脚本文件，不删数据库里的设备记录**——设备行的地址/凭据/绑定关系都保留，避免删一个文件连带销毁数据 |
| 删除后的设备 | 变成"孤儿"：列表里还在，但「设备类型」列显示原始 key，编辑/测试/封堵都会报 `未知设备类型` |
| 恢复 | 重新上传**同名**脚本即可，设备立刻恢复可用（`driver` 存的是 key，不是路径），配置不用重填 |
| 内置设备类型 | 不可被上传覆盖、也不可删除；同名会被直接拒绝 |

### 6.4 恶意脚本的风险与边界

先说结论：**设备脚本在 API 进程内执行，权限等同于服务进程本身**。平台提供的是准入控制与最小能力约束，不是沙箱隔离。

脚本一旦跑起来，可以做到：读取进程环境变量（数据库口令、`ENCRYPT_KEY` 等）、读写进程可访问的文件、访问容器网络可达的任意地址、修改进程内状态从而影响后续处置结果。所以下面两个假设**不成立**：静态检查能拦住恶意脚本；上传的脚本只影响它自己那台设备。

现有防线：

| 措施 | 作用 |
| --- | --- |
| 管理员准入 | 只有管理员能上传与删除 |
| 导入白名单 | 仅允许 2.2 列出的 24 个模块 |
| 危险符号禁用 | 禁 `eval`、`exec`、`compile`、`__import__`、`open`、`getattr`、`setattr` 与双下划线属性 |
| 目录隔离 | 上传脚本放在 `custom/`，与内置脚本分开；内置脚本不可覆盖、不可删除 |
| 上传审计 | 记录 sha256、大小、上传人、上传时间，并写一条 WARNING 日志 |
| 可撤销 | 页面「管理自定义脚本」一键删除，立即从注册表移除 |

这些措施的性质是：**减少误上传与低级恶意代码，不能防御有能力、有动机的攻击者**。真正的隔离需要执行环境，而不是代码检查。

按成本从低到高，可选加固：

1. **准入与核对**：只上传自研或已审阅的脚本，管理员账号控制到最小范围；定期核对磁盘脚本与台账哈希是否一致。
2. **专用实例**：把自定义设备脚本放到单独的 `alert-responder` 实例上，该实例只放通必要设备网段、使用独立凭据，主实例只跑内置设备类型。
3. **容器加固**：给运行自定义脚本的实例加 `read_only: true`、`cap_drop: [ALL]`、`security_opt: ["no-new-privileges:true"]`、`tmpfs: /tmp`，并用网络策略把出站限制到设备网段。
4. **架构演进**：把脚本调用下沉到独立 runner（子进程或独立容器），平台只传 IP 与配置、接收结果，ABI 不变。这样脚本再恶意，破坏面也被限制在 runner 内——这是唯一能真正防住的方案。

---

## 七、验证清单

**上传脚本**（常规路径）：

1. 页面上传 → 设备类型下拉里出现 `display_name` 即为注册成功；失败不会落盘，直接在弹窗里报错。
2. 后台确认加载与审计：

   ```bash
   sudo docker logs alert-responder 2>&1 | grep -E "自定义设备脚本|设备脚本加载失败"
   sudo docker exec alert-responder cat app/response/devices/custom/.meta.json
   ```

**内置脚本开发**（改平台仓库里的 `devices/*.py`）：

1. 脚本放进 `alert-responder/app/response/devices/`（随镜像分发），然后重建：

   ```bash
   sudo docker compose -f /home/zdby/SenseMind/docker-compose.yml up -d --build alert-responder
   ```

2. 看是否注册成功（加载失败只记日志，页面下拉里不会出现该项）：

   ```bash
   sudo docker logs alert-responder 2>&1 | grep -E "设备脚本加载失败|设备脚本 key 重复"
   ```

3. 跑自检（用 `MockTransport` 打全链路，不需要真实设备，也覆盖内置脚本）：

   ```bash
   sudo docker exec alert-responder python -m app.response.selftest
   sudo docker exec -e SENSEMIND_SELFTEST_DB=1 alert-responder python -m app.response.selftest   # 含存储层
   ```

**通用验证**：

1. 表单字段与 `config_schema` 一致（`depends_on` 字段随上游选择显隐）。
2. 真机顺序：先「测试连接」（只验证登录/握手）→ 再建一条联动处置，用白名单外的测试 IP 走一次封堵 → 在设备侧核对黑名单条目与描述 → 解除封堵确认幂等。
3. 重复封堵同一个 IP 两次，确认第二次不报错。
4. 解除一个本来就没封的 IP，确认不报错。
5. 故意填错密码，确认「测试连接」报的是登录失败而不是超时。

---

## 八、故障排查

| 现象 | 原因与处理 |
| --- | --- |
| 上传报「不允许导入 xxx」 | 用了白名单外的模块，见 2.2。最常见是 `httpx` / `os` / `__future__` |
| 上传报「不允许调用 getattr()」 | 见 2.3，改用 `dict.get` |
| 上传报「不允许访问双下划线属性」 | 用了 `.__class__` / `.__name__` / `super().__init__()`，见 2.3 |
| 上传报「同名设备已存在」 | `display_name` 与其他设备类型重复，改成独有的名字 |
| 上传报「已存在同名脚本」 | 同 key 已存在，确认覆盖即可 |
| 上传报「MANIFEST.key 必须与文件名一致」 | 改了 `MANIFEST["key"]` 忘了改文件名（或反之） |
| 上传报「API_VERSION 不匹配」 | 脚本里写了 `API_VERSION` 且与平台（当前 `1`）不一致，删掉这行或改成 1 |
| 下拉里没有新设备类型 | 加载失败：查服务日志，通常是 `config_schema` 缺 `name/label/type`、`select` 缺 `choices`、声明了平台保留字段名 |
| 表单里某字段不显示 | 该字段有 `depends_on`，上游字段当前值不匹配 |
| 保存报 `未知配置项` | 提交了清单外的键；加字段要改脚本 `config_schema` 并递增 `schema_version` |
| 保存报 `缺少必填项` | 新建时必填项为空；编辑时仅敏感字段允许留空沿用旧值 |
| 编辑设备报 `未知设备类型` | 该设备的设备脚本已被删除。重新上传同名脚本即恢复 |
| 设备凭据无法解密 | `ENCRYPT_KEY` 变了（换了 `.env`），需在页面重新保存该设备配置 |
| 测试连接超时 | 自签证书设备须关「校验证书」；确认 `alert-responder` 容器到设备管理口的路由与端口放通 |
| 登录被拒绝或权限不足 | 账号未授予黑名单模块权限、设备限制了登录来源 IP、没关双因素/验证码；部分设备还需单独开启 API 并建 API 专用账号 |
| 封堵记录成功但设备侧无记录 | 脚本把厂商业务失败当成功了，见 5.1 / 5.2；或设备侧对象组未被策略引用，见 5.13 |
| 封堵了但流量还能通 | 写进去的只是对象组/地址簿，没被安全策略引用；或写进了与策略无关的第二张名单 |
| 联动日志一片失败但设备侧其实封住了 | 回查逻辑判反了，或把回查的网络异常当成了"未生效"，见 5.4 |
| 同一个失败被反复重试、越试越乱 | 厂商业务拒绝被标成了 `retryable=True`，人工或外部调度照着重试；平台本身不重放，见 3.4 |
| 第二次解封报错 | 没做幂等，见 5.3 |
| 多次封堵后条目丢失 | 读-改-写接口并发覆盖，见 5.8 |
| 容器日志里找不到脚本日志 | 用了 `print`，见 5.15 |

---

## 九、内置设备类型接入说明

以下设备类型随镜像发布，直接在「添加联动设备」里选即可。

### 9.1 设备侧账号准备（通用）

各厂商账号体系不同：有的有**独立的 RESTful API 账号体系**（须先启用 API，再建 API 角色账号，普通 WebUI 管理员不能替代）；有的没有独立 API 角色，API 调用的就是设备本地**管理员账户**，按角色权限模板授权。

**无论哪种设备，都新建专用账号给平台用，不要复用默认 `admin`**。理由：

- 权限最小化：封堵只需要「地址黑名单 / 地址对象」模块的读写权限，不需要策略下发、系统升级、配置备份权限。
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

### 9.2 奇安信防火墙

脚本：`qianxin_firewall.py`。

字段与填写：

| 字段 | 说明 |
| --- | --- |
| 管理地址 | 含协议与端口，如 `https://10.0.0.1:8443`；也有 `http://<ip>:8080` 的部署，按设备实际填 |
| 用户名 / 密码 | **RESTful API 账号**（不是普通 WebUI 管理员） |

账号准备：

1. **启用 RESTful API**：`系统配置` → `设备管理` → `本机设置` → `RESTful API`，开启后接口才可访问。
2. **新建 RESTful API 用户**：`系统配置` → `设备管理` → `管理账号` → 新建账号，角色选 **`RESTful API管理员`**。账号名任意（示例用 `api-admin`）；接口权限按该角色模板授予，换成普通 WebUI 管理员角色可能缺少 API 调用权限。该账号需覆盖 `威胁处置 → 人工处置` 的读写权限，否则封禁与解封会返回非 0 的 `error_code`。
3. **添加可信主机**（设备启用了「管理主机」时必须做）：`系统配置` → `设备管理` → `管理主机` → 添加可信主机，添加时选择 **RESTful API** 类型，并填入 `alert-responder` 所在服务器的出口 IP。

封堵落点：**`处置中心` → `人工处置`** 里的网络连接处置项（`module=threat_disposal`），三条 function：

| 动作 | function | body 要点 |
| --- | --- | --- |
| 查是否已存在 | `get_threat_disposal` | `{"threat_disposal_cfg_ext": {"operation": "", "is_later": "no", "disposal_filter": {"status": "", "searchkey": "<ip>", "expired": "0", "datatype": "", "source": ""}}}`，`head` 带 `page_index`/`page_size`（每页最多 100）；`searchkey` 是模糊查询，须按返回项的 `sip`/`dip` 精确比对 |
| 添加 | `add_threat_disposal` | `{"threat_disposal_cfg_ext": {"is_later": "no", "threat_disposal_cfg": [{...}]}}`，单条处置项见下 |
| 删除（解封主路径） | `del_threat_disposal` | `{"threat_disposal_cfg_ext": {"is_later": "no", "threat_disposal_cfg": [{...}]}}`，字段与添加同构、无 `operation`。一次删除即解除阻断并把记录从列表移除。列表里历史遗留的「待响应」记录也用同一接口直接删，不做「先恢复处置再删」的来回改状态 |
| 撤销（兜底） | `set_threat_disposal` | 同结构再加 `operation: "revoke"`；**只在删除被拒时才发**。撤销只解除阻断、把记录置为「待响应」，记录仍留在列表里，因此不作为首选 |

**封禁固定下发两条处置项**：地址黑名单只对源地址生效，单条带 `sip` 或单条带 `dip` 都盖不住两个方向，所以每次封禁建两条——`sip=<ip>`（阻断该 IP 主动外连）与 `dip=<ip>`（阻断外部访问该 IP）。未填的另一个方向即 any，`proto`/`sport`/`dport` 留空表示不限；解封就是把这两条一次删掉。处置项其余字段固定为 `ipv4:"yes"`、`action:"block"`、`source:"manual"`、`datatype:"connection"`、`timeout:"forever"`（`timeout` 也可取 86400 / 604800 / 2592000 / 7776000）。

查询接口的 `searchkey` 未必能命中目的地址方向，脚本在按 IP 查不到时会退化为全量比对，避免重复下发或漏删。

接口调用顺序：

1. `POST /v1.0/login`，body `{"username": ..., "password": ...}` → 返回 `__s_sessionid__` cookie 与 `result.token`。
2. 业务请求统一 `POST /v1.0/rest/`，body 为列表，用 `head.module` + `head.function` 分发，成功判据是 `head.error_code` 为 0。
3. 结束 `POST /v1.0/out/` 退登。

**批量**：接口形态允许，但**未真机验证，暂按单 IP 下发**。两点依据：①添加人工处置的 `threat_disposal_cfg` 是数组，一条 body 里可以放多条五元组，官方文档没有写单次上限；②`/v1.0/rest/` 的 body 本身是 command 列表，理论上一次可提交多条 command、响应按顺序返回，能逐条判成败。另外设备还有一套独立的「批量黑 IP」接口（官方规格：一次最多 1000 个），但它的落点不是「处置中心 → 人工处置」，拦截效果与解除方式都不同，**不能替代**上面的封禁落点。

能力位：`test` = true（连接测试为登录 + 退登），`list_blocked` = false，`ipv6` = false。

### 9.3 深信服防火墙

脚本：`sangfor_af.py`。

字段与填写：

| 字段 | 说明 |
| --- | --- |
| 管理地址 | 含协议与端口，如 `https://10.0.0.1:443` |
| 用户名 / 密码 | 设备管理员账户 |
| 命名空间 | 默认 `@namespace`，单机部署不用动；只有设备开了多虚拟系统才需要填实际命名空间。它对应接口路径里的 `/api/v1/namespaces/<命名空间>/...` 这一段，`@namespace` 就是根系统的固定标识 |

账号准备：为管理员账号开启 Web API 管理方式——`系统` → `管理员账号` → 选中用户 → `登录安全设置` → `管理方式` → 勾选 `Web API`（`WEB控制台` 可同时保留）。未勾选时登录返回 `无管理方式权限`，并非密码错误。多虚拟系统场景下该账号需在所填命名空间内存在。

封堵落点：`安全运营` → `黑白名单` → `黑名单` → `永久封锁名单`（接口 `/api/v1/namespaces/{ns}/whiteblacklist`，`type=BLACK`；该接口没有有效期字段，写入的条目只出现在「永久封锁名单」，不会进「临时封锁名单」）。

接口调用顺序：

1. `POST /api/v1/namespaces/{ns}/login`，body `{"name": ..., "password": ...}` → `data.loginResult.token`，后续请求带 `Cookie: token=<token>`。
2. 黑名单：`POST/DELETE/GET .../whiteblacklist`，body `{"type": "BLACK", "url": "<ip>", "enable": true, "description": "SenseMind联动封禁"}`。
3. 结束 `POST /api/v1/namespaces/{ns}/logout`。

判成功不能只看 `message == "成功"`，须与 `code` 一起判（两者任一为成功态即视为成功）。封堵前先 `GET .../whiteblacklist/<ip>`，已在黑名单则跳过；解封时 IP 不存在同样视为成功（幂等）。

**「是否已封禁」要兼容固件差异**：部分固件返回 `urlType: "ip"`，部分固件**不回 `urlType`**，改用 `domain: 0` 表示非域名（即 IP 对象）。只认 `urlType` 会把已封禁误判成未封禁——表现为解封被"跳过"、封堵重复下发、回查永远判未生效。判定条件应为 `enable=true` 且 `type=BLACK` 且（`urlType == "ip"`，或 `urlType` 缺失时 `domain` 为 0）。

**IP 已经在白名单里就封不掉，报冲突不报成功**：同一个 IP 在设备上只能有一条名单记录，已经在白名单里的 IP 加不进黑名单。此时 `GET .../whiteblacklist/<ip>` 会返回**存在但 `type=WHITE`** 的条目（不算已封禁），而 `POST` 新增会被设备拒绝并回 `{"code": 17, "message": "黑白名单[\"<ip>\"] 已存在"}`。脚本的做法是：查到同名非黑名单条目就直接抛 `blacklist_conflict`（不可重试），提示「`<ip>` 已经在设备白名单里，与封禁冲突，请先在设备上移除这条白名单（或改成黑名单）再下发封禁」，**不替用户改配置**；解封时遇到白名单/停用条目也只是记 INFO、不删除（那是人工配置，不是平台下发的）。设备侧确实要改的话，官方接口是 `PATCH /api/v1/namespaces/{ns}/whiteblacklist/{url}`（8.2.7），body `{"obj": {"url": ..., "type": "BLACK", "enable": true, "description": ...}}`——但转换后原白名单条目就没了，需人工确认后再做。

**处置后回查**：设备返回成功后脚本会再 `GET` 一次确认实际状态——封禁后须查到 `enable=true` 且 `type=BLACK` 且为 IP 对象，解封后须查不到条目；明确不符则抛 `block_not_effective` / `unblock_not_effective`（可重试），联动日志记 `failed`，**不会写 `blocked=true`**。回查请求本身异常（网络抖动、查询接口报错）只记 WARNING、仍按设备返回结果处理，避免把已生效的操作误判成失败而与设备实际状态相反。

「资源不存在」优先看语义码 `code=1004`，中文文案（`黑白名单[...] 不存在`）只作兜底，这样设备换固件或语言包仍可用。`list_blocked` 已实现，按 `data.totalPages` 每页 200 翻页，逐页记 INFO 日志并在结尾记总条数。

**批量**：**支持**（官方 8.2.4 / 8.2.5）。添加走 `POST /api/batch/v1/namespaces/{ns}/whiteblacklist`，body 与单条相同但 `obj` 是数组：

```json
{"obj": [{"url": "1.1.1.1", "type": "BLACK", "enable": true, "description": "SenseMind联动封禁"}]}
```

可选 query `override` 决定冲突处理：`PROMPT`（默认，冲突报错）、`REPLACE`（冲突替换）、`SKIP`（冲突跳过）、`SKIPBACK`（冲突返回）、`PROMPTALL`（返回全部冲突原因）。批量删除是 `POST /api/batch/v1/namespaces/{ns}/whiteblacklist?_method=delete`，body 同为 `obj` 数组。

判成败时注意：响应顶层的 `code`/`message` 只代表整体受理结果，每个 `obj` 会带回 `blockRes`（封锁结果）和 `blockMsg`（原因），**要按条目逐个看**，不能只凭顶层 `code` 判定全部成功。

上面只是设备能力，`block` 仍然只封一个 IP：平台不会把 IP 列表传进来，别在脚本里攒批次再下发（攒批次会把“哪个 IP 失败”这一个信息丢掉）。

### 9.4 天融信防火墙

脚本：`topsec_firewall.py`。

字段与填写：

| 字段 | 说明 |
| --- | --- |
| 管理地址 | 含协议与端口，如 `https://10.0.0.1:443` |
| 用户名 / 密码 | 设备管理员账号；密码填**明文**，脚本按设备要求自行加密后提交 |

账号准备：用设备管理员账号，需具备「安全策略 → 黑白名单 → 静态黑名单」的读写权限。登录有两个接口：优先 `POST /home/restLogin/`，该接口不存在（404）时自动改走 `POST /home/login/addNoCode/`。**建议把设备上的登录验证码关掉**——不同版本固件的验证码机制不一样，开着可能挡住其中一个接口。

封堵落点：`安全策略 → 黑白名单 → 静态黑名单`。

**接口 A：`blackWhite`**（新固件，条目 `mark=ip`，带 `ipaddr` + `direction`）：

| 动作 | 请求 |
| --- | --- |
| 查是否已存在 | `GET /home/default/blackWhite/addrStaticBlackSearch/`，`commands[0][pf_blacklist_static_search][detail]=<ip>`（可选 `[from]=1`、`[num]=20`）；返回 `rows[]` 里看 `ipaddr` 与 `direction` |
| 添加 | `POST /home/default/blackWhite/whiteIpAdd/`，`commands[0][blacklist_cfg_add_ip][ipaddr]=<ip>`，另带 `enable=yes`、`direction=src\|dst`、`except_priv_ip=off`、`comment`；`group_name` 只在策略组接口查到组时才带（见下） |
| 删除 | `POST /home/default/blackListSpread/deleteLots/`，`commands[0][blacklist_cfg_delete_ip][0][ipaddr]=<ip>`（按 IP 下发，该地址各方向条目一并清掉） |

**接口 B：`blackListSpread`**（老固件，条目 `mark=tuple`，是五元组：封源写 `sip`、封目的写 `dip`，其余维度不填即「不限」）：

| 动作 | 请求 |
| --- | --- |
| 查是否已存在 | `GET /home/default/blackListSpread/showAll/`，`commands[0][pf_blacklist_show_all]=`（空值，一次返回全量，不分页）；`rows[]` 里五元组看 `sip`/`dip`，地址段看 `ip_start`/`ip_end`（`mark=range`） |
| 添加 | `POST /home/default/blackListSpread/add/`，源方向 `commands[0][pf_blacklist_add][sip]=<ip>`，目的方向 `commands[0][pf_blacklist_add][dip]=<ip>` |
| 删除 | `POST /home/default/blackListSpread/deleteLots/`，`commands[0][pf_blacklist_delete][0][sip]=…&[sport]=…&[dip]=…&[dport]=…&[l4_protocol]=…`，**按查询返回的那一条原值下发完整五元组**，不限的维度传空串 |

**怎么选**：先用 `GET /home/default/blackWhite/showPolicyGroup/`（`commands[0][blacklist_profile_group_show][from]=1`、`[num]=20`）探路——返回 `result:true` 说明 `blackWhite` 接口可用，走 A；返回 `{"result":false,"data":"cfg文件不存在"}` 说明该设备没有这套接口配置，走 B。**探针不能用「添加」**：3.7 的静态黑名单同一 IP 只允许一条记录，添加被拒（`ip黑名单添加存在错误`）不等于接口不可用。老固件上 `blackWhite` 的三个接口会分别回 `无效输入，分析错误` / `cfg文件不存在`，添加侧无论带不带 `group_name` 都拿不到 `result:true`；同一台设备上 `blackListSpread` 的增删查全部可用，页面手动建的条目也是这套接口的五元组形态（`mark=tuple`）。

**策略组要查出来再填，查不到就不填**：`group_name` 在接口里标为可选，但填设备上不存在的组，设备会去打开该组的 cfg 文件并回 `cfg文件不存在`，添加直接失败。所以组名只能来自策略组接口返回——有 `default_group` 就用它，否则用第一个组；返回空列表则不传。

**源方向必封，目的方向尽力**：接口 A 先下发 `direction=src`（只有它拦得住攻击源主动发来的流量，`dst` 只匹配「发往该 IP」的报文），设备拒绝只记日志；若因已有其它方向条目被拒（3.7 同一 IP 只允许一条记录），先删旧条目再按 `src` 重建。接口 B 则先下发 `sip=<ip>`、再尝试 `dip=<ip>`，`sip` 那条被拒算失败，`dip` 被拒只记日志。

**五元组只能按条目删**：该模块上没有「按 IP 删」的可用命令（`commands[0][blacklist_cfg_delete_ip][0][ipaddr]` 在这里回 `{"result":false,"data":"c"}`），必须用查询返回的原值下发 `pf_blacklist_delete`。人工建的地址段条目接口不支持删除，脚本只记告警。

`token` 与 `codeRun` 一律放 query，命令字段放表单（GET 则全部在 query）——设备按这个形态校验，放错位置同样报 `Parameter tampered`。

**token 是链式轮转的**：官方文档原文「每执行一个 api 都会生成新的 token，执行下一个 api 时，需将上一个 api 产生的 token 作为参数赋予新的 api」。所以一次处置里必须从每个响应前缀 `?[TOKEN}?` 里取最新 token 再算下一次的 `codeRun`，不能登录后一直用同一个；也因此**同一台设备不能并发处置**——两条处置线会互相覆盖 token 状态。

参数键必须保持**字面量**：`commands[0][pf_blacklist_add][sip]` 里的 `[` `]` 不能被百分号编码（`%5B`/`%5D`），否则设备解析不出命令，返回 `{"result":false,"data":"无效输入，分析错误"}`。所以 query 与表单串都要手工拼（只编码值），不能用现成的 `urlencode(dict)`。

调用约定：

1. **登录** `POST /home/restLogin/`，表单 `name` + `password` + `ngtosAuth`。`password` 与 `ngtosAuth`（加密后的明文长度）都用 AES-CBC 加密（密钥与偏移量均为 16 个 `1`、零填充、输出 base64）。响应是普通 JSON：`data.authid` 作为 userMark，`secret` 在顶层或 `data` 内并参与 codeRun 计算，token 取 `tokens` 数组（优先第 2 个）。该方式建立的会话必须用 `GET /home/restLogout/` 退登（`commands` 为 `{}` 且参与 codeRun），用 `/home/index/logout/` 会返回 `Parameter tampered`。
   老固件没有该接口（返回 HTTP 404），此时脚本自动改走 `POST /home/login/addNoCode/`，表单 `name` + `password` + `pwdlen`；密码用 AES-CBC 但密钥与偏移量换成 `ngfwrestapilogin`，`pwdlen` 是明文长度。响应正文是 base64 JSON：`data.authid` 作为 userMark，`data.secret` 参与 codeRun 计算，退登用 `/home/index/logout/`。
2. **公共参数**：除登录外每个请求都必须带登录返回的 Cookie、`Referer: <base>/html/webui/home.html/?userMark=<userMark>`、`Content-Type: application/x-www-form-urlencoded`。
3. **token**：取响应里 `?[` 与 `}?` 之间的字符串；**每次请求都会换新的**，下一次请求必须用最新的。
4. **codeRun** = `md5(secret + token + url + commands 的 JSON)`，`url` 是不带参数的路径。`commands` 必须按**设备侧的数组形态**序列化：`commands[0][pf_blacklist_add][sip]=<ip>` 对应 `[{"pf_blacklist_add":{"sip":"<ip>"}}]`，**不能**把下标当对象键写成 `{"0":{...}}`，否则设备返回 `Parameter tampered`。
5. **判成功**：响应 `{"result":true,...}`；`{"result":false,"data":"原因"}` 为失败。查询结果在 `rows[]` 里：静态黑名单条目看 `ipaddr`（`mark=ip`）与 `direction`，五元组条目看 `sip`/`dip`（有值的维度是字符串，不限的维度是空数组），地址段条目看 `ip_start`/`ip_end`（`mark=range`）。

**批量**：**不支持**。token 是链式轮转的（见「封堵落点」里的说明），每个请求都必须用上一条响应用的 token 重新算 `codeRun`，一次请求只承载一条命令。所以只能逐 IP 下发。

能力位：`test` = true，`list_blocked` = false，`ipv6` = false。

### 9.5 绿盟 NF 防火墙

脚本：`nsfocus_nf.py`。

字段与填写：

| 字段 | 说明 |
| --- | --- |
| 管理地址 | 含协议与 API 端口，如 `https://10.0.0.1:8081`（官方默认 8081） |
| API Token | 设备 Web 界面「系统管理 → API 管理」生成 |

账号准备：Token 继承生成者的权限，用具备「策略配置 → 全局黑白名单」读写权限的管理员生成；设备重置或 Token 吊销后需更新配置。

调用约定：

1. **认证**是静态 Token，不登录、不换会话：每个请求带 `Authorization: <token>`（裸值，不加 `Bearer`）与 `Content-Type: application/json`；前缀固定 `/north/nf`。
2. **封堵落点**：策略配置 → 全局黑白名单 → 黑名单（`/north/nf/strategy/globalWb/blist`）：

| 动作 | 请求 |
| --- | --- |
| 查是否已存在 | `GET /north/nf/strategy/globalWb/blist/info/?size=<n>&page=<n>&search=<ip>`（`size=-1` 取全量） |
| 添加 | `POST .../blist/configuration/`，`{"action":"create","type":"sourceIp","ip":"<ip>","protocol":"any","objectType":"ip","port":"any","is_time":"f","status":true}` |
| 删除 | `POST .../blist/delete/`，`{"id":[<条目 id>]}`，id 取自查询结果 |

3. **判成功**：响应 `{"status":2000,"module":"NF","message":...}`；`status` 有 int `2000` 与字符串 `"2000"` 两种形态，按字符串比较；失败看 `message`。
4. **查询语义**：`search` 只用来缩小范围，是否已存在一律按返回项的 `ip` 字段精确比对；若 `total` 非 0 但本页没有目标 IP（`search` 只回部分结果），退化为 `size=-1` 全量再比对一次。
5. **处置后回查**：新建/删除后再查一次——封禁后须查到该 IP，解封后须查不到；不符抛 `block_not_effective` / `unblock_not_effective`（可重试），联动日志记 `failed`，不写 `blocked=true`。
6. `type` 固定 `sourceIp`（封源地址，封目的地址改 `destIp`）；`objectType=ip` 按 IP 对象下发；时间限制固定关闭（`is_time=f`）。

能力位：`test` = true，`list_blocked` = true（`size=-1` 全量拉取），`ipv6` = false（接口带 `ipv6` 参数，未经真机验证不声明）。

### 9.6 山石网科防火墙

脚本：`hillstone_fw.py`。

字段与填写：

| 字段 | 说明 |
| --- | --- |
| 管理地址 | 含协议与 WebUI 端口，如 `https://10.0.0.1:8443`（443 / 8443 按设备实际） |
| API Token | 可选。有新版本 API Token 时填这里，优先使用；留空则用用户名密码 |
| 用户名 / 密码 | 有地址簿读写权限的账号；密码填明文，脚本按设备要求做 base64 |
| 地址簿组名 | 封禁 IP 写入该组，默认 `SenseMind-Block` |

前置条件：地址簿只是对象容器，**该组必须被安全策略引用**（源或目的地址）才会真正阻断流量。建议先手动建组并在策略里选好，再交给平台维护组内 IP；否则接口会返回成功但流量不受影响。

调用约定：

1. **登录**：`POST /rest/api/login`，三种 body 按顺序尝试——
   - Token：`{"api_token":"..."}`
   - 用户名密码（默认）：`{"lang":"en","userName":"<base64>","password":"<base64>"}`
   - 老固件兜底：`{"lang":"en","userName":"明文","password":"明文","encodeUserName":"0","encodePassword":"0"}`

   全部失败才算登录失败；从响应 `result[0]` 取 `token`/`role`/`vsysId`/`fromrootvsys`/`username`。
2. **会话**：后续请求带 `X-Auth-Token`/`X-Auth-Role`/`X-Auth-VsysId`/`X-Auth-Fromrootvsys`/`X-Auth-Username` 头、同名 Cookie（`fromrootvsys; role; vsysId; token; username; lang`）以及 `X-API-Language: en`。`401`/`403` 或 `error_code` 为 `loginError_1001/1002/1003` 时自动重登一次并重试该请求（设备侧行为就是 401、403 清会话），仍失败才报错；写请求返回 `400`/`415` 时改用 `text/plain;charset=UTF-8` 承载同一份 JSON 重试一次（个别固件只收这种），`Accept` 按 WebUI 客户端的值发送。
3. **地址簿**（`/rest/api/addrbook`）：
   - 查组：`GET ...?query={"conditions":[{"field":"name","value":"<组>"}],"start":0,"limit":200,"page":1}`
   - 建组：`POST`，body `[{"name":"<组>","ip":[{"ip_addr":"<ip>","netmask":"32","flag":0}]}]`
   - 改组：`PUT`，结构同上，**整体覆盖**组成员而非增量
4. **读-改-写**：增删 IP 都要先 `GET` 取组内全量 IP，改完 `PUT` 覆盖。并发封禁同一台设备时后写会覆盖先写，所以写入后一律回读，不符则重新读改写一次（最多 2 次），仍不符抛 `block_not_effective` / `unblock_not_effective`（可重试）。
5. **判成功**：HTTP 2xx 且响应没有 `success:false`、`error_code` 为空或 0；但**最终判据是回读**——组里查到该 IP 才算封禁成功。
6. 解封只移除 IP，不删组，保留空组以免策略引用断链。

能力位：`test` = true，`list_blocked` = true（读组取全量），`ipv6` = false（主机对象 `netmask` 固定 32）。

---

## 十、设计与约束

- 传输层只有 HTTP/HTTPS；只提供 CLI/SSH 处置入口的设备不适用本规范。
- `http_client()` 只做单向 TLS（可校验服务端证书、可带自定义 CA / 跳过校验），**不支持客户端证书（mTLS）**，也不支持 SOCKS 代理；厂商强制双向证书时当前接不了。
- `block` 只接受单 IP，不支持一次批量下发；`unblock` 必须幂等。部分厂商提供批量接口（见 9.2、9.3），但平台当前仍按单 IP 逐个下发，脚本不要假设会收到 IP 列表。
- 内置设备类型随镜像发布（改代码要重建镜像）；自定义脚本存在独立的命名卷里，重建容器不丢，上传即生效。
- 一台设备对应一条配置记录；同一物理设备上的多个虚拟系统按不同命名空间建多条记录。
- 设备类型保存后不可修改；换类型要删了重建，避免存量 `config` 语义错位。
