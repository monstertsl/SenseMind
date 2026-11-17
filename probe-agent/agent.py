"""SenseMind 探针 agent —— Python 长驻容器（合并原 probe-agent.sh + probe-logrotate 工具容器）

职责（单容器单循环，失败不阻塞，下轮重试；吊销检查优先）：
1. 健康采集：10 秒粒度，metrics_common 与中心同源同口径（Suricata 抓包面流量/丢包）
2. 心跳上报：每 5 分钟把暂存的时序点批量 POST /probe/health（中心落 PG system_metrics）
   —— 探针本地只暂存未上报点（JSONL，上报成功即清），历史真源在中心，保留策略共用
3. 配置下发：拉清单 → 哈希比对 → 下载校验 → 应用（规则热加载 / NTP 写入）
4. 原始日志轮转：每小时检查，logrotate 按 state 判定每日轮转（保留天数中心下发动态渲染）
5. 吊销停服：清单 revoked=true → 停兄弟容器 + 自停（unless-stopped 不复活）

执行环境（docker-compose-probe.yml）：
- network host（直连中心 8080）、TZ=Asia/Shanghai（logrotate dateext 对齐用户日历）
- 挂载：certs（mTLS）、/data/probe-agent（state+暂存）、docker.sock（exec suricata/停容器）、
  /data/suricata/logs 与 /data/zeek/logs（轮转）、/etc/systemd/timesyncd.conf（NTP 写入）
"""

import datetime as dt
import hashlib
import json
import logging
import os
import ssl
import subprocess
import tarfile
import time

import httpx

from metrics_common import (
    SuricataCounterWindow,
    collect_cpu_percent,
    collect_disk_usage,
    collect_memory_percent,
    warmup_cpu,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [probe-agent] %(levelname)s %(message)s")
log = logging.getLogger("probe-agent")

# ---- 环境与路径 ----
CENTER_HOST = os.environ.get("CENTER_HOST", "127.0.0.1")
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
CA_CERT = f"{CERT_DIR}/ca.crt"
CLIENT_CERT = f"{CERT_DIR}/client.crt"
CLIENT_KEY = f"{CERT_DIR}/client.key"
STATE_DIR = os.environ.get("STATE_DIR", "/data/probe-agent")
STATE_FILE = f"{STATE_DIR}/state.json"
BUFFER_FILE = f"{STATE_DIR}/health_buffer.jsonl"
RETENTION_FILE = f"{STATE_DIR}/retention"
BUFFER_MAX_BYTES = 5 * 1024 * 1024  # 暂存上限：超过截断保留尾部（防断网无限累积）

RULES_DIR = "/data/suricata/lib/rules"
TIMESYNCD_CONF = "/etc/systemd/timesyncd.conf"
NTP_PENDING = f"{STATE_DIR}/ntp.pending"  # deploy-probe 的 path unit 监听：触发宿主机 restart timesyncd

LOGROTATE_TMPL = "/etc/logrotate.d/logrotate-probe.conf.tmpl"
LOGROTATE_CONF = "/etc/logrotate.d/sensemind-raw-logs"
LOGROTATE_STATE = f"{STATE_DIR}/logrotate.status"

SURICATA_CONTAINER = os.environ.get("PROBE_SURICATA_CONTAINER", "probe-suricata")
PROBE_CONTAINERS = ["probe-filebeat", "probe-suricata", "probe-zeek"]
SELF_CONTAINER = os.environ.get("SELF_CONTAINER", "probe-agent")

COLLECT_INTERVAL = int(os.environ.get("COLLECT_INTERVAL", "10"))    # 秒（与中心 metric_collector 一致）
REPORT_INTERVAL = int(os.environ.get("REPORT_INTERVAL", "300"))     # 秒（心跳+批量上报周期）
ROTATE_CHECK_INTERVAL = int(os.environ.get("ROTATE_CHECK_INTERVAL", "3600"))  # 每小时检查轮转
RESOURCE_NAMES = ("rules-baseline", "rules-local", "ntp")

# mTLS：显式 SSLContext 加载客户端证书（httpx cert=tuple 在部分版本对
# nginx optional_verify 场景不发送客户端证书，实测 401；显式 context 稳定）
_tls_ctx = ssl.create_default_context(cafile=CA_CERT)
_tls_ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
_client = httpx.Client(verify=_tls_ctx, timeout=30, headers={"Accept": "application/json"})


def now_iso() -> str:
    return dt.datetime.utcnow().isoformat() + "Z"


def log_event(msg: str) -> None:
    log.info(msg)


# ---------- 健康采集与暂存 ----------

def append_buffer(point: dict) -> None:
    with open(BUFFER_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(point) + "\n")
    # 上限保护：超过 5MB 保留尾部一半（防长期断网无限累积）
    try:
        if os.path.getsize(BUFFER_FILE) > BUFFER_MAX_BYTES:
            with open(BUFFER_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            with open(BUFFER_FILE, "w", encoding="utf-8") as f:
                f.writelines(lines[len(lines) // 2:])
            log_event("健康暂存超限，已截断保留尾部")
    except OSError:
        pass


def collect_sample(window: SuricataCounterWindow, warm: list) -> dict | None:
    """采集一个采样点。首轮预热返回 None（cpu_percent 首次为 0.0）。"""
    if not warm[0]:
        warm[0] = True
        warmup_cpu()
        return None
    feed = window.feed()
    traffic_mbps, drops_delta = feed if feed else (0.0, 0)
    # 磁盘只报容量（used/total），使用率由中心按 used/total 计算——
    # 少上报一个字段，且百分比与容量天然一致（psutil percent 本就是 used/total）
    _, disk_used, disk_total = collect_disk_usage("/data")
    return {
        "ts": now_iso(),
        "cpu_percent": round(collect_cpu_percent(), 1),
        "memory_percent": round(collect_memory_percent(), 1),
        "traffic_mbps": traffic_mbps,
        "drops_delta": drops_delta,
        "disk_used": int(disk_used),
        "disk_total": int(disk_total),
    }


def report_health() -> None:
    """批量上报暂存点。成功即清空 buffer；失败保留（断网累积、恢复补报）。"""
    if not os.path.exists(BUFFER_FILE) or os.path.getsize(BUFFER_FILE) == 0:
        return
    with open(BUFFER_FILE, "r", encoding="utf-8") as f:
        points = [json.loads(line) for line in f if line.strip()]
    if not points:
        return
    resp = _client.post(f"https://{CENTER_HOST}:8080/api/v1/probe/health",
                        json={"points": points})
    if resp.status_code == 200 and resp.json().get("code") == 0:
        accepted = resp.json()["data"]["accepted"]
        with open(BUFFER_FILE, "w", encoding="utf-8") as f:
            f.write("")
        log_event("健康时序上报成功: %d/%d 点" % (accepted, len(points)))
    else:
        log_event("健康上报失败 HTTP %s（暂存保留，下轮补报）" % resp.status_code)


# ---------- 清单：吊销 / 保留天数 / 配置下发 ----------

def shutdown_on_revoke() -> None:
    """吊销自我停服：停兄弟容器 + 自停（unless-stopped：手动 stop 后宿主机重启不复活）。"""
    log_event("清单返回 revoked=true，执行自我停服")
    with httpx.Client(transport=httpx.HTTPTransport(uds="/var/run/docker.sock"), timeout=30) as dc:
        for c in PROBE_CONTAINERS + [SELF_CONTAINER]:
            try:
                dc.post(f"http://docker/containers/{c}/stop")
                log_event("已停止容器: %s" % c)
            except Exception as e:
                log_event("停止容器 %s 失败（继续）: %s" % (c, e))
    os._exit(0)  # 双保险：即使 docker.sock stop 自身失败也退出进程


def load_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def apply_resource(res: str, tmp_path: str) -> bool:
    """应用已校验的下载物。返回是否成功。"""
    if res in ("rules-baseline", "rules-local"):
        # 解包写入规则目录（包内文件名即规则文件名，覆盖写）
        try:
            with tarfile.open(tmp_path) as tf:
                tf.extractall(RULES_DIR, filter="data")  # 包由中心发布器确定性生成
        except (tarfile.TarError, OSError) as e:
            log_event("解包失败: %s: %s" % (res, e))
            return False
        for name in os.listdir(RULES_DIR):
            os.chmod(os.path.join(RULES_DIR, name), 0o644)
        # suricata 热加载（语法校验已在中心发布前完成）
        code, _ = _docker_exec(SURICATA_CONTAINER, ["suricatasc", "-c", "reload-rules"])
        if code != 0:
            log_event("规则热加载失败（suricata 容器未运行?）: %s" % res)
            return False  # 规则文件已落盘，下轮重试 reload
        log_event("规则已应用并热加载: %s" % res)
        return True

    if res == "ntp":
        # 下载物即 ntp.json 原文：{"ntp_servers": "..."}
        with open(tmp_path, "r", encoding="utf-8") as f:
            servers = (json.load(f).get("ntp_servers") or "").strip()
        if not servers:
            return True
        try:
            with open(TIMESYNCD_CONF, "r", encoding="utf-8") as f:
                lines = f.readlines()
            out, found = [], False
            for line in lines:
                if line.startswith("NTP=") or line.startswith("#NTP="):
                    out.append("NTP=%s\n" % servers)
                    found = True
                else:
                    out.append(line)
            if not found:
                out.append("NTP=%s\n" % servers)
            with open(TIMESYNCD_CONF, "w", encoding="utf-8") as f:
                f.writelines(out)
            # 宿主机 path unit（deploy-probe 安装）监听 pending 文件触发 restart timesyncd
            with open(NTP_PENDING, "w", encoding="utf-8") as f:
                f.write(servers)
            log_event("NTP 配置已应用: %s" % servers)
            return True
        except OSError as e:
            log_event("NTP 写入失败: %s" % e)
            return False
    return False


def _docker_exec(container: str, cmd: list) -> tuple:
    """docker.sock exec（探针侧 suricata 热加载等）。返回 (exit_code, output)。"""
    from metrics_common import _exec_in_container
    return _exec_in_container(container, cmd)


def process_manifest(state: dict) -> dict:
    """拉清单：吊销检查 → 保留天数同步 → 资源哈希比对 → 下载校验应用。"""
    resp = _client.get(f"https://{CENTER_HOST}:8080/api/v1/probe/config/manifest")
    data = resp.json()["data"]

    # 吊销检查（F14）：证书有效即可拿到信号，触发即停服终止进程
    if data.get("revoked"):
        shutdown_on_revoke()

    # 原始日志保留天数同步（与中心 scheduler 常量同源）
    retention = data.get("raw_log_file_retention_days", 3)
    if not isinstance(retention, int) or retention < 1:
        retention = 3
    with open(RETENTION_FILE, "w", encoding="utf-8") as f:
        f.write(str(retention))

    # 哈希比对，挑出有变资源
    changed = []
    for res in RESOURCE_NAMES:
        want = (data.get("resources", {}).get(res) or {}).get("sha256", "")
        have = state.get(res, "")
        if want and want != have:
            changed.append((res, want))
        if not want and have:
            state.pop(res, None)  # 中心侧已清空该资源
    if not changed:
        save_state(state)
        return state

    # 逐资源下载 + 校验 + 应用
    for res, sha in changed:
        tmp = f"{STATE_DIR}/{res}.download"
        try:
            with open(tmp, "wb") as f:
                with _client.stream("GET", f"https://{CENTER_HOST}:8080/api/v1/probe/config/resource/{res}") as r:
                    for chunk in r.iter_bytes():
                        f.write(chunk)
        except Exception as e:
            log_event("下载失败: %s: %s" % (res, e))
            continue
        actual = hashlib.sha256(open(tmp, "rb").read()).hexdigest()
        if actual != sha:
            log_event("哈希校验失败: %s" % res)
            os.remove(tmp)
            continue
        if apply_resource(res, tmp):
            state[res] = sha
        os.remove(tmp)
    save_state(state)
    return state


# ---------- 原始日志轮转（原 probe-logrotate 工具容器逻辑合并） ----------

def render_logrotate_conf() -> None:
    """按中心下发的保留天数渲染 logrotate 配置（maxage/rotate 双保险）。"""
    try:
        retention = int(open(RETENTION_FILE, encoding="utf-8").read().strip())
    except (OSError, ValueError):
        retention = 3
    if retention < 1:
        retention = 3
    tmpl = open(LOGROTATE_TMPL, encoding="utf-8").read()
    conf = tmpl.replace("__MAXAGE__", str(retention))
    with open(LOGROTATE_CONF, "w", encoding="utf-8") as f:
        f.write(conf)


def run_logrotate() -> None:
    """每小时调用；不带 -f，logrotate 按 state 判定每日一次（幂等）。"""
    render_logrotate_conf()
    try:
        subprocess.run(
            ["logrotate", "-s", LOGROTATE_STATE, LOGROTATE_CONF],
            capture_output=True, timeout=7200,
        )
    except subprocess.TimeoutExpired:
        log_event("logrotate 超时（本轮放弃，不影响主循环）")
    except Exception as e:
        log_event("logrotate 调用失败: %s" % e)


# ---------- 主循环 ----------

def main() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    if not os.path.exists(STATE_FILE):
        save_state({})
    state = load_state()
    window = SuricataCounterWindow(SURICATA_CONTAINER)
    warm = [False]  # CPU 预热标记（首轮采集丢弃）

    log_event("探针 agent 启动（采集 %ds / 心跳 %ds / 轮转检查 %ds）"
              % (COLLECT_INTERVAL, REPORT_INTERVAL, ROTATE_CHECK_INTERVAL))

    next_report = 0.0
    next_rotate_check = 0.0
    while True:
        tick = time.time()
        try:
            point = collect_sample(window, warm)
            if point:
                append_buffer(point)
        except Exception as e:
            log_event("采集异常（继续）: %s" % e)

        if tick >= next_report:
            next_report = tick + REPORT_INTERVAL
            try:
                report_health()  # 心跳 + 批量时序（失败保留暂存）
            except Exception as e:
                log_event("健康上报异常（暂存保留）: %s" % e)
            try:
                state = process_manifest(state)  # 吊销/保留天数/配置下发
            except Exception as e:
                log_event("清单处理异常（下轮重试）: %s" % e)

        if tick >= next_rotate_check:
            next_rotate_check = tick + ROTATE_CHECK_INTERVAL
            try:
                run_logrotate()
            except Exception as e:
                log_event("轮转异常（继续）: %s" % e)

        time.sleep(max(0.0, COLLECT_INTERVAL - (time.time() - tick)))


if __name__ == "__main__":
    main()
