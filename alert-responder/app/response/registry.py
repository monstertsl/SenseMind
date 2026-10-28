"""设备脚本注册表。

扫描 devices/ 目录，逐个校验 MANIFEST 与函数签名后注册。加一个设备 = 加一个 .py 文件，
不改注册代码；任何清单/签名不合规都直接加载失败，不允许静默跳过。
"""

import importlib.util
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from sensemind_device import API_VERSION

logger = logging.getLogger(__name__)

DEVICES_DIR = Path(__file__).parent / "devices"

REQUIRED_FUNCS = ("block", "unblock")
OPTIONAL_FUNCS = ("setup", "teardown", "test_connection", "list_blocked")
REQUIRED_MANIFEST_KEYS = ("key", "display_name", "schema_version", "config_schema")
FIELD_TYPES = {"text", "password", "url", "int", "bool", "select", "textarea"}
# 平台字段由运行时统一消费，脚本再用同名声明会覆盖平台策略
RESERVED_FIELD_NAMES = {"timeout_seconds", "verify_tls", "ca_cert_pem", "max_concurrency"}


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
    )


def scan(force: bool = False) -> dict:
    """返回 {key: DriverSpec}；加载失败的脚本记日志后不注册。"""
    cache = getattr(scan, "_cache", None)
    if cache is not None and not force:
        return cache
    specs = {}
    for path in sorted(DEVICES_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            spec = _build_spec(path)
        except DriverLoadError as exc:
            logger.error("设备脚本加载失败：%s", exc)
            continue
        if spec.key in specs:
            logger.error("设备脚本 key 重复，已跳过：%s", spec.key)
            continue
        specs[spec.key] = spec
    scan._cache = specs
    return specs


def get(key: str) -> DriverSpec:
    spec = scan().get(key)
    if spec is None:
        logger.error("请求了未注册的设备驱动：%s", key)
        raise DriverLoadError(f"未知设备类型：{key}")
    return spec


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
        }
        for spec in scan().values()
    ]
