"""探针管理路由

- admin_router（/api/v1/probes）：Web 设备管理页，admin 鉴权（F16）
- probe_router（/api/v1/probe）：探针侧注册接口，token/mTLS 即凭证（F9/F3）
"""

import datetime as dt
import hashlib
import json
import logging
import os
import secrets
import uuid
from typing import List, Optional

from fastapi.responses import FileResponse

from ..core.probe_config import RESOURCE_NAMES, load_manifest, resource_path

import httpx  # noqa: F401  (保持与其他路由一致的依赖风格)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.auth import require_role, AuthContext
from ..core.audit import write_system_log
from ..core.database import get_db
from ..db_models.probe_registry import ProbeRegistry
from ..db_models.system_config import SystemConfig
from ..schemas import ApiResponse

logger = logging.getLogger(__name__)

admin_router = APIRouter(prefix="/api/v1/probes", tags=["设备管理"])
probe_router = APIRouter(prefix="/api/v1/probe", tags=["探针接入"])

TOKEN_VALID_HOURS = 24          # 一次性 token 有效期（F9）
CERT_VALID_DAYS = 180           # 客户端证书有效期（F3）
CLOCK_SKEW_MINUTES = 5          # 证书生效时间提前量，容忍时钟偏差

PROBE_CA_CERT = os.environ.get("PROBE_CA_CERT", "/usr/share/ai-analyzer/certs/probe-ca.crt")
PROBE_CA_KEY = os.environ.get("PROBE_CA_KEY", "/usr/share/ai-analyzer/certs/probe-ca.key")


# ---------- 工具 ----------

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _new_probe_uid(db: Session) -> str:
    for _ in range(10):
        uid = f"prb-{secrets.token_hex(4)}"
        exists = db.execute(
            select(ProbeRegistry).where(ProbeRegistry.probe_uid == uid)
        ).scalar_one_or_none()
        if not exists:
            return uid
    raise HTTPException(status_code=500, detail="内部 ID 生成失败，请重试")


def _load_ca():
    """加载探针 CA（证书+私钥）。缺失时给出明确错误。"""
    if not (os.path.exists(PROBE_CA_CERT) and os.path.exists(PROBE_CA_KEY)):
        raise HTTPException(
            status_code=500,
            detail="探针 CA 未初始化：缺少 probe-ca.crt/probe-ca.key（由中心 deploy.sh 初始化生成）",
        )
    with open(PROBE_CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(PROBE_CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    return ca_cert, ca_key


def _sign_csr(csr_pem: bytes, probe_uid: str):
    """用探针 CA 为 CSR 签发客户端证书（CN=内部 ID，clientAuth，180 天）。"""
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except ValueError:
        raise HTTPException(status_code=400, detail="CSR 格式无效，需为 PEM 编码")
    if not csr.is_signature_valid:
        raise HTTPException(status_code=400, detail="CSR 签名无效")

    ca_cert, ca_key = _load_ca()
    now = dt.datetime.now(dt.timezone.utc)
    not_after = now + dt.timedelta(days=CERT_VALID_DAYS)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, probe_uid)]))
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=CLOCK_SKEW_MINUTES))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        format(cert.serial_number, "x"),
        not_after,
    )


def _client_ip(request: Request) -> str:
    # 探针请求经 nginx 反代，真实 IP 取 X-Forwarded-For 首段
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


def _initial_config(db: Session) -> dict:
    """注册响应携带的初始配置（当前为 NTP，后续随清单扩展）。"""
    cfg = db.execute(select(SystemConfig).where(SystemConfig.id == 1)).scalar_one_or_none()
    return {"ntp_servers": (cfg.ntp_servers or "") if cfg else ""}


def _probe_to_dict(p: ProbeRegistry, now: dt.datetime) -> dict:
    # token 展示状态：待使用 / 已使用 / 已过期
    token_state = ""
    if p.status == "pending" and p.token_hash:
        if p.token_expires_at and p.token_expires_at.replace(tzinfo=None) < now:
            token_state = "已过期"
        else:
            token_state = "待使用"
    # 在线判定：active 且最近 15 分钟内有健康上报
    online = False
    if p.status == "active" and p.last_report_at:
        online = (now - p.last_report_at.replace(tzinfo=None)) <= dt.timedelta(minutes=15)
    return {
        "probe_uid": p.probe_uid,
        "name": p.name,
        "site": p.site,
        "status": p.status,
        "token_state": token_state,
        "online": online,
        "registered_at": p.registered_at.isoformat() + "Z" if p.registered_at else None,
        "registered_ip": p.registered_ip,
        "last_report_at": p.last_report_at.isoformat() + "Z" if p.last_report_at else None,
        "cert_not_after": p.cert_not_after.isoformat() + "Z" if p.cert_not_after else None,
        "health": json.loads(p.last_health) if p.last_health else None,
    }


def _parse_health(request: Request) -> str:
    """解析探针健康上报 query 参数（F7），返回 JSON 字符串；非法/缺失字段忽略。

    cpu/mem/disk：0-100 百分比；rx_bps/tx_bps：字节每秒增量；drop_pct：0-100。
    """
    q = request.query_params
    health = {}
    try:
        for k in ("cpu", "mem", "disk"):
            v = q.get(k)
            if v is not None:
                f = float(v)
                if 0 <= f <= 100:
                    health[k] = round(f, 1)
        for k in ("rx_bps", "tx_bps"):
            v = q.get(k)
            if v is not None:
                f = float(v)
                if 0 <= f <= 1e12:
                    health[k] = round(f)
        v = q.get("drop_pct")
        if v is not None:
            f = float(v)
            if 0 <= f <= 100:
                health["drop_pct"] = round(f, 2)
    except (ValueError, TypeError):
        pass
    return json.dumps(health) if health else ""


def _get_probe(db: Session, probe_uid: str) -> ProbeRegistry:
    p = db.execute(
        select(ProbeRegistry).where(ProbeRegistry.probe_uid == probe_uid)
    ).scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="探针不存在")
    return p


def _validate_name(name: str, field: str) -> str:
    value = (name or "").strip()
    if len(value) > 100:
        raise HTTPException(status_code=400, detail=f"{field}过长（上限 100 字符）")
    return value


# ---------- 管理端（F16） ----------

class TokenCreateBody(BaseModel):
    name: str
    site: str = ""
    rebind_uid: str = ""  # 重装场景：绑定已有内部 ID，覆盖签发（F9 ④）


@admin_router.get("")
def list_probes(db: Session = Depends(get_db), current_user: AuthContext = Depends(require_role("admin"))):
    rows = db.execute(
        select(ProbeRegistry).order_by(ProbeRegistry.created_at.desc())
    ).scalars().all()
    now = dt.datetime.utcnow()
    return ApiResponse(code=0, message="ok",
                       data=[_probe_to_dict(p, now) for p in rows],
                       request_id=str(uuid.uuid4()))


@admin_router.post("/token")
def create_token(body: TokenCreateBody, request: Request,
                 db: Session = Depends(get_db),
                 current_user: AuthContext = Depends(require_role("admin"))):
    name = _validate_name(body.name, "备注名")
    site = _validate_name(body.site, "站点")
    token = secrets.token_urlsafe(24)
    now = dt.datetime.utcnow()

    if body.rebind_uid:
        # 重装：绑定已有内部 ID，覆盖签发（旧证书序列号加入吊销标记，F9 ④）
        probe = _get_probe(db, body.rebind_uid)
        if probe.status == "pending":
            raise HTTPException(status_code=400, detail="该探针尚未完成注册，直接使用已有 token 即可")
        if probe.cert_serial:
            probe.add_revoked_serial(probe.cert_serial)
        probe.cert_serial = ""
        probe.cert_not_after = None
        probe.status = "pending"
        probe.registered_ip = ""
    else:
        probe = ProbeRegistry(probe_uid=_new_probe_uid(db), name=name, site=site)

    probe.name = name
    probe.site = site
    probe.token_hash = _hash_token(token)
    probe.token_expires_at = now + dt.timedelta(hours=TOKEN_VALID_HOURS)
    probe.token_used_at = None
    db.add(probe)
    db.commit()

    write_system_log(db, action="probe_token_create", target_type="probe",
                     detail=f"生成探针接入 token: {probe.probe_uid}（{name}）"
                            + ("，重装覆盖签发" if body.rebind_uid else ""),
                     operator=current_user.username, ip_address=_client_ip(request))
    return ApiResponse(code=0, message="ok", data={
        "probe_uid": probe.probe_uid,
        "name": name,
        "site": site,
        "token": token,  # 仅此一次返回
        "expires_at": probe.token_expires_at.isoformat() + "Z",
    }, request_id=str(uuid.uuid4()))


class ProbeUpdateBody(BaseModel):
    name: Optional[str] = None
    site: Optional[str] = None


@admin_router.put("/{probe_uid}")
def update_probe(probe_uid: str, body: ProbeUpdateBody, request: Request,
                 db: Session = Depends(get_db),
                 current_user: AuthContext = Depends(require_role("admin"))):
    probe = _get_probe(db, probe_uid)
    changed = {}
    if body.name is not None:
        probe.name = _validate_name(body.name, "备注名")
        changed["name"] = probe.name
    if body.site is not None:
        probe.site = _validate_name(body.site, "站点")
        changed["site"] = probe.site
    if not changed:
        raise HTTPException(status_code=400, detail="没有需要修改的字段")
    db.commit()
    write_system_log(db, action="probe_update", target_type="probe",
                     detail=f"修改探针备注: {probe_uid} {changed}",
                     operator=current_user.username, ip_address=_client_ip(request))
    return ApiResponse(code=0, message="ok", data=_probe_to_dict(probe, dt.datetime.utcnow()),
                       request_id=str(uuid.uuid4()))


@admin_router.post("/{probe_uid}/revoke")
def revoke_probe(probe_uid: str, request: Request,
                 db: Session = Depends(get_db),
                 current_user: AuthContext = Depends(require_role("admin"))):
    probe = _get_probe(db, probe_uid)
    if probe.status == "revoked":
        raise HTTPException(status_code=400, detail="该探针已是吊销状态")
    if probe.cert_serial:
        probe.add_revoked_serial(probe.cert_serial)
    probe.status = "revoked"
    db.commit()
    # 吊销状态随后经配置下发清单传递，探针自我停服（F14，P9 阶段接入）
    write_system_log(db, action="probe_revoke", target_type="probe",
                     detail=f"吊销探针: {probe_uid}（{probe.name}）",
                     operator=current_user.username, ip_address=_client_ip(request))
    return ApiResponse(code=0, message="ok", data=_probe_to_dict(probe, dt.datetime.utcnow()),
                       request_id=str(uuid.uuid4()))


@admin_router.delete("/{probe_uid}")
def delete_probe(probe_uid: str, request: Request,
                 db: Session = Depends(get_db),
                 current_user: AuthContext = Depends(require_role("admin"))):
    probe = _get_probe(db, probe_uid)
    db.delete(probe)
    db.commit()
    write_system_log(db, action="probe_delete", target_type="probe",
                     detail=f"手动删除探针注册表条目: {probe_uid}（{probe.name}）",
                     operator=current_user.username, ip_address=_client_ip(request))
    return ApiResponse(code=0, message="ok", data=None, request_id=str(uuid.uuid4()))


# ---------- 探针侧（F9/F3） ----------

class RegisterBody(BaseModel):
    token: str
    csr: str  # PEM 编码 CSR


@probe_router.post("/register")
def register(body: RegisterBody, request: Request, db: Session = Depends(get_db)):
    token_hash = _hash_token(body.token.strip())
    probe = db.execute(
        select(ProbeRegistry).where(ProbeRegistry.token_hash == token_hash)
    ).scalar_one_or_none()
    if not probe:
        raise HTTPException(status_code=403, detail="注册 token 无效")
    if probe.status != "pending":
        raise HTTPException(status_code=403, detail="注册 token 已被使用或探针已吊销")
    now = dt.datetime.utcnow()
    if not probe.token_expires_at or probe.token_expires_at.replace(tzinfo=None) < now:
        raise HTTPException(status_code=403, detail="注册 token 已过期，请重新生成")

    cert_pem, serial, not_after = _sign_csr(body.csr.encode(), probe.probe_uid)
    probe.status = "active"
    probe.token_used_at = now
    probe.registered_at = now
    probe.registered_ip = _client_ip(request)
    probe.cert_serial = serial
    probe.cert_not_after = not_after
    db.commit()

    logger.info("探针注册成功: %s (%s) 来源 %s", probe.probe_uid, probe.name, probe.registered_ip)
    return ApiResponse(code=0, message="ok", data={
        "probe_uid": probe.probe_uid,
        "cert": cert_pem.decode(),
        "initial_config": _initial_config(db),
    }, request_id=str(uuid.uuid4()))


class RenewBody(BaseModel):
    csr: str


def _auth_probe(request: Request, db: Session, check_serial: bool = True):
    """mTLS 探针身份校验（续签/配置下发共用）：nginx 转发的客户端证书 → CN=内部 ID → 注册表。

    check_serial=True（续签）时同时拒绝已标记吊销的旧证书序列号；
    配置下发场景为 False（证书有效即可拉配置，吊销走清单 revoked 字段触发自我停服）。
    返回 (probe, probe_uid)。
    """
    import urllib.parse

    cert_header = request.headers.get("X-Client-Cert", "")
    if not cert_header:
        raise HTTPException(status_code=401, detail="缺少客户端证书（需 mTLS 接入，见 F8）")
    try:
        cert_pem = urllib.parse.unquote(cert_header).encode()
        cert = x509.load_pem_x509_certificate(cert_pem)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="客户端证书无效")
    ca_cert, _ = _load_ca()
    try:
        cert.verify_directly_issued_by(ca_cert)
    except Exception:
        raise HTTPException(status_code=401, detail="客户端证书不受信任")

    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    probe_uid = cn_attrs[0].value if cn_attrs else ""
    probe = _get_probe(db, probe_uid)
    if check_serial and serial_hex_of(cert) in probe.revoked_serials():
        raise HTTPException(status_code=403, detail="该证书已吊销")
    return probe, probe_uid


def serial_hex_of(cert) -> str:
    return format(cert.serial_number, "x")


@probe_router.post("/renew")
def renew(body: RenewBody, request: Request, db: Session = Depends(get_db)):
    """mTLS 续签：客户端证书由 nginx 校验并以 X-Client-Cert 头转发（P5 配置）。

    吊销状态或已标记吊销的旧证书序列号一律拒绝。
    """
    probe, probe_uid = _auth_probe(request, db)
    if probe.status == "revoked":
        raise HTTPException(status_code=403, detail="探针已吊销")

    new_cert_pem, new_serial, not_after = _sign_csr(body.csr.encode(), probe_uid)
    if probe.cert_serial:
        probe.add_revoked_serial(probe.cert_serial)
    probe.cert_serial = new_serial
    probe.cert_not_after = not_after
    db.commit()
    return ApiResponse(code=0, message="ok", data={
        "probe_uid": probe_uid,
        "cert": new_cert_pem.decode(),
    }, request_id=str(uuid.uuid4()))


# ==============================
# 配置下发（F6/F13，P6）：mTLS 探针身份，清单 + 资源下载
# ==============================

@probe_router.get("/config/manifest")
def config_manifest(request: Request, db: Session = Depends(get_db)):
    """下发清单 + 健康上报（F6/F7 同一请求）。

    探针比对本地哈希，仅下载有变资源；revoked=true 时探针自我停服（F14）。
    健康 query 参数（cpu/mem/disk/rx_bps/tx_bps/drop_pct）随拉取上报，入库注册表，
    存活判定 = 最近健康上报时间（F7）。
    raw_log_file_retention_days：探针本地原始日志保留天数，与中心 scheduler
    常量同源（logs 目录固定保留，不受存储优化页参数控制），agent 据此清理本地归档。
    """
    from ..scheduler import RAW_LOG_FILE_RETENTION_DAYS

    probe, probe_uid = _auth_probe(request, db, check_serial=False)
    manifest = load_manifest()
    # 健康上报（F7）：带参数则入库；即使无参数也更新 last_report_at（拉取即存活信号）
    health_json = _parse_health(request)
    probe.last_report_at = dt.datetime.utcnow()
    if health_json:
        probe.last_health = health_json
    db.commit()
    return ApiResponse(code=0, message="ok", data={
        "probe_uid": probe_uid,
        "revoked": probe.status == "revoked",
        "raw_log_file_retention_days": RAW_LOG_FILE_RETENTION_DAYS,
        **manifest,
    }, request_id=str(uuid.uuid4()))


class HealthPoint(BaseModel):
    """单个健康采样点（与 system_metrics 列对齐）。ts 为探针侧 UTC ISO 时间。"""
    ts: str
    cpu_percent: float
    memory_percent: float
    traffic_mbps: float = 0.0
    drops_delta: int = 0
    disk_percent: Optional[float] = None


class HealthReportBody(BaseModel):
    points: List[HealthPoint]


@probe_router.post("/health")
def report_health(body: HealthReportBody, request: Request, db: Session = Depends(get_db)):
    """探针健康时序批量上报（mTLS）。

    探针 agent 10 秒粒度采集（与中心 metric_collector 同一份共享模块、同 Suricata 口径），
    本地暂存未上报点，每 5 分钟心跳时批量推送；断网期间累积、恢复后补报。
    中心逐点范围校验后写入 system_metrics（probe_id=探针内部 ID），与中心自身
    时序同表共存，保留策略共用 metric_retention_days。最后一点同时更新注册表
    last_health 快照（设备管理页"健康状态"列展示，P7 语义不变）。
    """
    from ..db_models.system_metric import SystemMetric

    probe, _ = _auth_probe(request, db, check_serial=False)

    def _ok(v: float, lo: float, hi: float) -> float | None:
        return round(v, 1) if lo <= v <= hi else None

    rows = []
    last_snapshot = {}
    last_ts = None
    for pt in body.points[:3000]:  # 上限保护：单次最多 3000 点（≈8.3h@10s）
        cpu = _ok(pt.cpu_percent, 0, 100)
        mem = _ok(pt.memory_percent, 0, 100)
        if cpu is None or mem is None:
            continue  # 必填项非法的点整点丢弃（防脏数据）
        disk = _ok(pt.disk_percent, 0, 100) if pt.disk_percent is not None else None
        traffic = _ok(pt.traffic_mbps, 0, 1e6)
        drops = max(int(pt.drops_delta), 0) if 0 <= pt.drops_delta <= 2**31 else 0
        try:
            ts = dt.datetime.fromisoformat(pt.ts.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, TypeError):
            continue
        rows.append(SystemMetric(
            created_at=ts, probe_id=probe.probe_uid,
            cpu_percent=cpu, memory_percent=mem,
            traffic_mbps=traffic if traffic is not None else 0.0,
            drops_delta=drops, disk_percent=disk,
        ))
        # 快照取"时间最新"的点（列表顺序不代表时间顺序）
        if last_ts is None or ts > last_ts:
            last_ts = ts
            last_snapshot = {
                "cpu": cpu, "mem": mem, "disk": disk,
                "traffic_mbps": traffic if traffic is not None else 0.0,
                "kernel_drops_delta": drops,
            }

    if rows:
        db.add_all(rows)
    # 心跳信号 + 最新快照（快照字段名与 P7 manifest query 上报对齐，设备管理页无感）
    probe.last_report_at = dt.datetime.utcnow()
    if last_snapshot:
        probe.last_health = json.dumps(last_snapshot)
    db.commit()
    return ApiResponse(code=0, message="ok", data={"accepted": len(rows)}, request_id=str(uuid.uuid4()))


@probe_router.get("/config/resource/{name}")
def config_resource(name: str, request: Request, db: Session = Depends(get_db)):
    """资源下载：mTLS + 资源名白名单校验，FileResponse 流式返回"""
    _auth_probe(request, db, check_serial=False)
    if name not in RESOURCE_NAMES:
        raise HTTPException(status_code=404, detail="未知资源")
    path = resource_path(name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="资源未发布")
    return FileResponse(path, media_type="application/octet-stream", filename=name)
