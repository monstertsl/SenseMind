"""设备脚本注册表。

扫描 devices/ 目录，逐个校验 MANIFEST 与函数签名后注册。加一个设备 = 加一个 .py 文件，
不改注册代码；任何清单/签名不合规都直接加载失败，不允许静默跳过。
"""

import ast
import hashlib
import importlib.util
import json
import logging
import re
import shutil
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from sensemind_device import API_VERSION

logger = logging.getLogger(__name__)

DEVICES_DIR = Path(__file__).parent / "devices"
# 上传的脚本放这里，与内置脚本隔离：内置只读随镜像发布，自定义可删可覆盖
CUSTOM_DIR = DEVICES_DIR / "custom"
UPLOAD_TMP_DIR = CUSTOM_DIR / ".upload"
UPLOAD_META = CUSTOM_DIR / ".meta.json"
# 可下载的示例脚本；放在 templates/ 下，不会被加载
TEMPLATES_DIR = Path(__file__).parent / "templates"
EXAMPLE_SCRIPT = TEMPLATES_DIR / "example_vendor.py"

REQUIRED_FUNCS = ("block", "unblock")
OPTIONAL_FUNCS = ("setup", "teardown", "test_connection", "list_blocked")
REQUIRED_MANIFEST_KEYS = ("key", "display_name", "schema_version", "config_schema")
# 未声明 order 的设备排在已声明之后
DEFAULT_ORDER = 100
FIELD_TYPES = {"text", "password", "url", "int", "bool", "select", "textarea"}
# 平台字段由运行时统一消费，脚本再用同名声明会覆盖平台策略
RESERVED_FIELD_NAMES = {"timeout_seconds", "verify_tls", "ca_cert_pem", "max_concurrency"}
# 上传脚本的文件名（不含 .py）即 MANIFEST.key，规则与 Python 标识符一致
SCRIPT_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_SCRIPT_BYTES = 256 * 1024
# 上传脚本的静态检查采用白名单：设备脚本只做协议交互，不需要进程/文件/动态执行能力
ALLOWED_IMPORTS = {
    "base64",
    "collections",
    "contextlib",
    "dataclasses",
    "datetime",
    "enum",
    "hashlib",
    "hmac",
    "http",
    "ipaddress",
    "json",
    "logging",
    "math",
    "random",
    "re",
    "secrets",
    "string",
    "struct",
    "textwrap",
    "time",
    "typing",
    "urllib",
    "uuid",
    "sensemind_device",
}
FORBIDDEN_BUILTINS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "dir",
    "input",
    "breakpoint",
}
# 白名单外的导入一律拒绝，这里只列出常见误用，便于给出更明确的提示
HINT_IMPORTS = {"os", "sys", "subprocess", "socket", "ctypes", "importlib", "shutil", "pickle"}


class DriverLoadError(Exception):
    """脚本清单或实现不合规；加载期直接失败，避免运行到封堵时才炸。"""


@dataclass(frozen=True)
class DriverSpec:
    key: str
    display_name: str
    schema_version: int
    config_schema: list
    secret_fields: tuple
    capabilities: dict
    path: Path
    module: object
    funcs: dict = field(default_factory=dict)
    # 下拉展示顺序：小的在前，未声明的一律靠后；同值时按 key 排
    order: int = DEFAULT_ORDER
    # True = 后台上传的脚本（custom/ 下），可删除、可覆盖；False = 随镜像发布的内置脚本
    custom: bool = False
    # 上传元数据（仅 custom）：sha256、大小、上传人、时间
    meta: dict = field(default_factory=dict)

    def call(self, name: str) -> Optional[Callable]:
        return self.funcs.get(name)


def _validate_schema(key: str, schema) -> tuple:
    if not isinstance(schema, list) or not schema:
        raise DriverLoadError(f"{key}: config_schema 必须是非空列表")
    secret_fields = []
    seen = set()
    for index, item in enumerate(schema):
        if not isinstance(item, dict):
            raise DriverLoadError(f"{key}: config_schema[{index}] 必须是对象")
        for required in ("name", "label", "type"):
            if not item.get(required):
                raise DriverLoadError(f"{key}: config_schema[{index}] 缺少 {required}")
        name = item["name"]
        if name in seen:
            raise DriverLoadError(f"{key}: config_schema 字段重复 {name}")
        if name in RESERVED_FIELD_NAMES:
            raise DriverLoadError(f"{key}: 字段 {name} 是平台保留名，不能由脚本声明")
        if item["type"] not in FIELD_TYPES:
            raise DriverLoadError(f"{key}: 字段 {name} 的 type={item['type']} 不支持")
        if item["type"] == "select" and not item.get("choices"):
            raise DriverLoadError(f"{key}: select 字段 {name} 必须提供 choices")
        if item.get("depends_on") is not None and not isinstance(item["depends_on"], dict):
            raise DriverLoadError(f"{key}: 字段 {name} 的 depends_on 只能是单层对象")
        seen.add(name)
        if item.get("secret"):
            secret_fields.append(name)
    return tuple(secret_fields)


def _load_module(path: Path, key: str):
    module_name = f"sensemind_device_drivers.{key}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise DriverLoadError(f"{key}: 无法从 {path.name} 构建模块")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise DriverLoadError(f"{key}: 执行 {path.name} 失败（{type(exc).__name__}: {exc}）") from exc
    return module


def _build_spec(path: Path) -> DriverSpec:
    key = path.stem
    module = _load_module(path, key)
    manifest = getattr(module, "MANIFEST", None)
    if not isinstance(manifest, dict):
        raise DriverLoadError(f"{key}: 缺少 MANIFEST 字典")
    for required in REQUIRED_MANIFEST_KEYS:
        if manifest.get(required) in (None, "", []):
            raise DriverLoadError(f"{key}: MANIFEST 缺少 {required}")
    if manifest["key"] != key:
        raise DriverLoadError(f"{key}: MANIFEST.key（{manifest['key']}）必须与文件名一致")
    module_version = getattr(module, "API_VERSION", API_VERSION)
    if module_version != API_VERSION:
        raise DriverLoadError(f"{key}: API_VERSION 不匹配（脚本 {module_version} / 平台 {API_VERSION}）")

    schema_version = manifest["schema_version"]
    if not isinstance(schema_version, int) or schema_version < 1:
        raise DriverLoadError(f"{key}: schema_version 必须是 >=1 的整数")

    order = manifest.get("order", DEFAULT_ORDER)
    if not isinstance(order, int) or isinstance(order, bool) or order < 0:
        raise DriverLoadError(f"{key}: order 必须是非负整数")

    secret_fields = _validate_schema(key, manifest["config_schema"])

    funcs = {}
    for name in REQUIRED_FUNCS:
        if not callable(getattr(module, name, None)):
            raise DriverLoadError(f"{key}: 缺少必需函数 {name}")
        funcs[name] = getattr(module, name)
    for name in OPTIONAL_FUNCS:
        func = getattr(module, name, None)
        if callable(func):
            funcs[name] = func

    # 能力位由实现反推，避免清单里声明了但函数没写
    capabilities = {
        "test": "test_connection" in funcs,
        "list_blocked": "list_blocked" in funcs,
        "ipv6": bool((manifest.get("capabilities") or {}).get("ipv6", False)),
    }
    return DriverSpec(
        key=key,
        display_name=str(manifest["display_name"]),
        schema_version=schema_version,
        config_schema=manifest["config_schema"],
        secret_fields=secret_fields,
        capabilities=capabilities,
        path=path,
        module=module,
        funcs=funcs,
        order=order,
    )


def scan(force: bool = False) -> dict:
    """返回 {key: DriverSpec}；加载失败的脚本记日志后不注册。"""
    cache = getattr(scan, "_cache", None)
    if cache is not None and not force:
        return cache
    specs = {}
    sources = [(path, False) for path in sorted(DEVICES_DIR.glob("*.py"))]
    sources += [(path, True) for path in sorted(CUSTOM_DIR.glob("*.py"))]
    meta = _read_meta()
    for path, is_custom in sources:
        if path.name.startswith("_"):
            continue
        try:
            spec = _build_spec(path)
        except DriverLoadError as exc:
            logger.error("%s脚本加载失败：%s", "自定义" if is_custom else "内置", exc)
            continue
        if spec.key in specs:
            logger.error("设备脚本 key 重复，已跳过：%s", spec.key)
            continue
        if is_custom:
            spec = replace(spec, custom=True, meta=dict(meta.get(spec.key) or {}))
        specs[spec.key] = spec
    # 按 order 排（同 order 按 key），让下拉、日志与 manifests 顺序一致且不随文件名漂移
    specs = dict(sorted(specs.items(), key=lambda item: (item[1].order, item[0])))
    scan._cache = specs
    return specs


def get(key: str) -> DriverSpec:
    spec = scan().get(key)
    if spec is None:
        logger.error("请求了未注册的设备类型：%s", key)
        raise DriverLoadError(f"未知设备类型：{key}")
    return spec


def _check_source(key: str, source: str) -> None:
    """上传脚本的静态检查：语法 + 导入白名单 + 危险内建/属性。

    只能抬高门槛，不能替代隔离——脚本最终仍在 API 进程内执行，
    进程内可见的环境变量、数据库连接与网络它对脚本都是可达的。
    """
    try:
        tree = ast.parse(source, filename=f"{key}.py")
    except SyntaxError as exc:
        raise DriverLoadError(f"{key}: 语法错误（第 {exc.lineno} 行：{exc.msg}）") from None
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _check_import(key, alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            _check_import(key, (node.module or "").split(".")[0])
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_BUILTINS:
                raise DriverLoadError(f"{key}: 不允许调用 {func.id}()")
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__"):
                raise DriverLoadError(f"{key}: 不允许访问双下划线属性 {node.attr}")
        elif isinstance(node, ast.Name) and node.id in {"__builtins__", "__loader__", "__spec__"}:
            raise DriverLoadError(f"{key}: 不允许引用 {node.id}")


def _check_import(key: str, root: str) -> None:
    if root in ALLOWED_IMPORTS:
        return
    if root in HINT_IMPORTS:
        raise DriverLoadError(f"{key}: 不允许导入 {root}（设备脚本只能做协议交互，网络请求走 sensemind_device）")
    allowed = "、".join(sorted(ALLOWED_IMPORTS))
    raise DriverLoadError(f"{key}: 不允许导入 {root}；可用模块：{allowed}")


def _read_meta() -> dict:
    try:
        return json.loads(UPLOAD_META.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_meta(data: dict) -> None:
    CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
    tmp = UPLOAD_META.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(UPLOAD_META)


def _check_display_name(spec: DriverSpec) -> None:
    """设备类型名称必须全局唯一。

    下拉与设备列表只展示 display_name、不展示 key，同名会出现两个无法区分的选项，
    运维容易选错设备类型；因此在入口直接拒绝，而不是等到界面上产生歧义。
    """
    name = spec.display_name.strip().casefold()
    for other in scan().values():
        if other.key == spec.key:
            continue
        if other.display_name.strip().casefold() == name:
            raise DriverLoadError(
                f"同名设备已存在：设备类型名称「{spec.display_name}」已被 {other.key}.py 使用，"
                "请修改 MANIFEST 的 display_name 后重新上传"
            )


def install_script(
    filename: str, content: bytes, overwrite: bool = False, uploaded_by: str = ""
) -> DriverSpec:
    """安装上传的设备脚本到 custom/：先校验再落盘，校验不通过不改动任何文件。

    依次校验：扩展名与文件名（即 key）、体积、UTF-8 文本（拒绝二进制与 NUL）、静态检查、
    MANIFEST 与函数签名。脚本最终会被平台导入执行，因此调用方必须先做管理员鉴权。
    """
    name = (filename or "").strip()
    if not name.lower().endswith(".py"):
        raise DriverLoadError("脚本必须是 .py 文件")
    key = name[:-3]
    if not SCRIPT_KEY_RE.match(key):
        raise DriverLoadError(
            "文件名（去掉 .py）必须小写字母开头，只含小写字母/数字/下划线，长度 1-64，例如 vendor_device.py"
        )
    if not content:
        raise DriverLoadError("脚本内容为空")
    if len(content) > MAX_SCRIPT_BYTES:
        raise DriverLoadError(f"脚本不能超过 {MAX_SCRIPT_BYTES // 1024} KB")
    if b"\x00" in content:
        raise DriverLoadError("脚本不能包含 NUL 字节（仅支持 UTF-8 文本）")
    try:
        source = content.decode("utf-8")
    except UnicodeDecodeError:
        raise DriverLoadError("脚本必须是 UTF-8 编码的文本文件") from None

    _check_source(key, source)

    builtin_path = DEVICES_DIR / f"{key}.py"
    if builtin_path.exists():
        raise DriverLoadError(f"{key} 是内置脚本，不能用上传脚本覆盖；请换一个文件名")
    CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
    target = CUSTOM_DIR / f"{key}.py"
    if target.resolve().parent != CUSTOM_DIR.resolve():
        raise DriverLoadError("非法的脚本路径")
    if target.exists() and not overwrite:
        raise DriverLoadError(f"已存在同名脚本 {target.name}，确认覆盖后才能替换")

    UPLOAD_TMP_DIR.mkdir(exist_ok=True)
    workdir = Path(tempfile.mkdtemp(dir=UPLOAD_TMP_DIR))
    staged = workdir / f"{key}.py"
    try:
        staged.write_text(source, encoding="utf-8")
        spec = _build_spec(staged)
        _check_display_name(spec)
        shutil.move(str(staged), str(target))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    meta = _read_meta()
    meta[key] = {
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "uploaded_by": uploaded_by or "",
        "uploaded_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
    }
    _write_meta(meta)
    scan(force=True)
    # 从注册表重新取，确保返回值带 custom 标记与完整 meta
    installed = scan().get(key) or replace(spec, custom=True, meta=meta[key])
    logger.warning(
        "自定义设备脚本%s：%s（%s，操作人 %s）",
        "已覆盖" if overwrite else "已安装",
        target.name,
        installed.display_name,
        uploaded_by or "未知",
    )
    return installed


def uninstall_script(key: str) -> str:
    """删除上传的设备脚本；内置脚本不允许通过接口删除。"""
    name = (key or "").strip()
    if not SCRIPT_KEY_RE.match(name):
        raise DriverLoadError("非法的设备类型标识")
    target = CUSTOM_DIR / f"{name}.py"
    if not target.exists():
        if (DEVICES_DIR / f"{name}.py").exists():
            raise DriverLoadError(f"{name} 是内置脚本，不能删除")
        raise DriverLoadError(f"未找到自定义脚本 {name}.py")
    target.unlink()
    meta = _read_meta()
    if meta.pop(name, None) is not None:
        _write_meta(meta)
    scan(force=True)
    logger.warning("自定义设备脚本已删除：%s.py", name)
    return name


def example_script() -> tuple[str, str]:
    """返回可下载的示例脚本（文件名, 源码）。"""
    try:
        return EXAMPLE_SCRIPT.name, EXAMPLE_SCRIPT.read_text(encoding="utf-8")
    except OSError as exc:
        raise DriverLoadError(f"示例脚本不可用：{exc}") from None


def manifests() -> list:
    """供前端渲染「添加设备」下拉与动态表单。"""
    return [
        {
            "key": spec.key,
            "display_name": spec.display_name,
            "schema_version": spec.schema_version,
            "config_schema": spec.config_schema,
            "secret_fields": list(spec.secret_fields),
            "capabilities": spec.capabilities,
            "custom": spec.custom,
            "meta": spec.meta,
        }
        for spec in scan().values()
    ]
