"""探针配置发布器（F6/F13，P6）

中心侧将下发资源打包为探针可拉取的形式：
  - rules-baseline：规则目录下除 local.rules 外的全部 .rules 文件（基线规则包，大、极少变）
  - rules-local：local.rules 单文件（AI 生成规则，小、常变）
  - ntp：NTP 服务器配置（来自 system_config）

版本即内容哈希（SHA256）：每次发布先对源内容做指纹比对，无变化则跳过（发布节流，
保证探针清单稳定、避免版本抖动）；有变化才以**确定性打包**重建 tar.gz（固定 mtime/
uid/gid，同内容必同哈希），再更新 manifest.json。

发布产物目录（挂载 ./data/probe-config，rw）：
  PROBE_CONFIG_DIR/rules-baseline.tar.gz
  PROBE_CONFIG_DIR/rules-local.tar.gz
  PROBE_CONFIG_DIR/ntp.json
  PROBE_CONFIG_DIR/manifest.json
"""

import hashlib
import json
import logging
import os
import tarfile

logger = logging.getLogger(__name__)

# 发布产物目录（ai-analyzer 容器内，compose 挂载）
PROBE_CONFIG_DIR = os.environ.get(
    "PROBE_CONFIG_DIR", "/usr/share/ai-analyzer/probe-config"
)
# 中心规则工作区（compose 挂载 /data/suricata/lib/rules）
CENTER_RULES_DIR = os.environ.get("CENTER_RULES_DIR", "/suricata/rules")
# local.rules 在规则目录内的文件名（AI 生成规则 → local 包；其余 .rules → 基线包）
LOCAL_RULES_NAME = "local.rules"

# 资源名白名单（下载接口校验用）
RESOURCE_NAMES = ("rules-baseline", "rules-local", "ntp")

# 探针 agent 最低脚本版本（F13：新增配置类型需探针包升级支持时提升）
MIN_AGENT_VERSION = 1

_BASELINE_EXCLUDE = {LOCAL_RULES_NAME}
# 备份/临时文件不进基线包
_BASELINE_SUFFIX_EXCLUDE = (".bak", ".tmp", ".swp")


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _baseline_sources() -> dict:
    """基线包源文件清单：文件名 → 内容 sha256（备份/临时文件排除）"""
    out = {}
    if not os.path.isdir(CENTER_RULES_DIR):
        return out
    for name in sorted(os.listdir(CENTER_RULES_DIR)):
        p = os.path.join(CENTER_RULES_DIR, name)
        if name in _BASELINE_EXCLUDE or name.endswith(_BASELINE_SUFFIX_EXCLUDE):
            continue
        if os.path.isfile(p) and name.endswith(".rules"):
            out[name] = _sha256_file(p)
    return out


def _local_source() -> dict:
    """local 包源文件指纹：内容为空文件时返回空（探针跳过应用）"""
    p = os.path.join(CENTER_RULES_DIR, LOCAL_RULES_NAME)
    if not os.path.isfile(p):
        return {}
    content_hash = _sha256_file(p)
    if not os.path.getsize(p):
        return {}
    return {LOCAL_RULES_NAME: content_hash}


def _deterministic_tar(tar_path: str, files: dict) -> None:
    """确定性打包：固定 mtime/uid/gid/mode，同内容必同哈希"""
    tmp = tar_path + ".tmp"
    with tarfile.open(tmp, "w:gz") as tf:
        for name in sorted(files):
            p = os.path.join(CENTER_RULES_DIR, name)
            info = tf.gettarinfo(p, arcname=name)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            with open(p, "rb") as f:
                tf.addfile(info, f)
    os.replace(tmp, tar_path)


def _write_atomic(path: str, data: bytes) -> None:
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _publish_rules_package(res_name: str, sources: dict, state: dict) -> None:
    """打包规则包：源指纹无变化则跳过（节流），有变化才重建"""
    tar_path = os.path.join(PROBE_CONFIG_DIR, res_name + ".tar.gz")
    if not sources:
        # 无源（如 local.rules 为空）：移除旧包，清单中不含该资源
        if os.path.exists(tar_path):
            os.remove(tar_path)
        state.pop(res_name, None)
        return
    fingerprint = {k: v for k, v in sources.items()}
    if state.get(res_name + "_fp") == fingerprint and os.path.exists(tar_path):
        return
    _deterministic_tar(tar_path, sources)
    state[res_name + "_fp"] = fingerprint
    logger.info("探针配置资源已发布: %s（%d 个文件）", res_name, len(sources))


def _publish_ntp(state: dict, ntp_servers: str) -> None:
    ntp_path = os.path.join(PROBE_CONFIG_DIR, "ntp.json")
    payload = json.dumps({"ntp_servers": ntp_servers}, ensure_ascii=False,
                         sort_keys=True).encode()
    fp = hashlib.sha256(payload).hexdigest()
    if state.get("ntp_fp") == fp and os.path.exists(ntp_path):
        return
    _write_atomic(ntp_path, payload)
    state["ntp_fp"] = fp
    logger.info("探针 NTP 配置已发布")


def _read_ntp_servers() -> str:
    """从 system_config 读取 NTP 设置（失败返回空，探针保持现状）"""
    try:
        from sqlalchemy import select
        from .database import SessionLocal
        from ..db_models.system_config import SystemConfig

        db = SessionLocal()
        try:
            cfg = db.execute(
                select(SystemConfig).where(SystemConfig.id == 1)
            ).scalar_one_or_none()
            return (cfg.ntp_servers or "") if cfg else ""
        finally:
            db.close()
    except Exception as e:  # noqa: BLE001
        logger.warning("读取 NTP 配置失败: %s", e)
        return ""


def _build_manifest(state: dict) -> dict:
    resources = {}
    for res_name in ("rules-baseline", "rules-local"):
        tar_path = os.path.join(PROBE_CONFIG_DIR, res_name + ".tar.gz")
        if os.path.exists(tar_path):
            resources[res_name] = {
                "sha256": _sha256_file(tar_path),
                "size": os.path.getsize(tar_path),
            }
    ntp_path = os.path.join(PROBE_CONFIG_DIR, "ntp.json")
    if os.path.exists(ntp_path):
        resources["ntp"] = {
            "sha256": _sha256_file(ntp_path),
            "size": os.path.getsize(ntp_path),
        }
    return {
        "min_agent_version": MIN_AGENT_VERSION,
        "resources": resources,
        "_state": state,
    }


def publish_probe_config() -> dict:
    """发布节流主入口：比对源指纹 → 打包有变的资源 → 更新 manifest.json

    供 scheduler 每 5 分钟调用（F6 发布节流），也可手动触发。
    返回当前 manifest（不含内部 state）。
    """
    os.makedirs(PROBE_CONFIG_DIR, exist_ok=True)

    # state 持久化在 manifest.json 的 _state 字段（进程重启不丢节流指纹）
    manifest_path = os.path.join(PROBE_CONFIG_DIR, "manifest.json")
    state = {}
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path) as f:
                state = json.load(f).get("_state", {})
        except (json.JSONDecodeError, OSError):
            state = {}

    _publish_rules_package("rules-baseline", _baseline_sources(), state)
    _publish_rules_package("rules-local", _local_source(), state)
    _publish_ntp(state, _read_ntp_servers())

    manifest = _build_manifest(state)
    _write_atomic(manifest_path, json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, indent=1).encode())
    manifest.pop("_state", None)
    return manifest


def load_manifest() -> dict:
    """读取当前发布 manifest（无内部 state）"""
    manifest_path = os.path.join(PROBE_CONFIG_DIR, "manifest.json")
    if not os.path.exists(manifest_path):
        return {"min_agent_version": MIN_AGENT_VERSION, "resources": {}}
    try:
        with open(manifest_path) as f:
            m = json.load(f)
        m.pop("_state", None)
        return m
    except (json.JSONDecodeError, OSError):
        return {"min_agent_version": MIN_AGENT_VERSION, "resources": {}}


def resource_path(name: str) -> str:
    """资源文件路径（调用方需先校验 name ∈ RESOURCE_NAMES）"""
    if name == "ntp":
        return os.path.join(PROBE_CONFIG_DIR, "ntp.json")
    return os.path.join(PROBE_CONFIG_DIR, name + ".tar.gz")
