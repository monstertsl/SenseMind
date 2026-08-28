"""系统资源时序采集器 —— 5 秒粒度，写入 system_metrics 表

设计要点：
- 独立于 system_service.py（后者服务仪表盘实时快照 API，两者互不影响）。
- CPU 用 psutil.cpu_percent(interval=None) 非阻塞，避免每 5 秒阻塞 0.5 秒。
  （首次调用返回 0.0，需先预热一次）
- Suricata 计数通过 Docker Engine API（unix socket）在 suricata 容器内执行
  suricatasc -c dump-counters，与 rule_writer._exec_in_suricata 同一套机制，
  无需 docker CLI / SDK。
- 流量与丢包均按"增量"计算（相邻两次采样的差值），落库即增量值。
  查询长时间范围时丢包必须 SUM（增量可加）；用 AVG 会严重低估集中丢包。
"""

import json
import logging
import threading
import time

import httpx
import psutil

from ..core.database import SessionLocal
from ..db_models.system_metric import SystemMetric

logger = logging.getLogger(__name__)

DOCKER_SOCK = "/var/run/docker.sock"
SURICATA_CONTAINER = "suricata"
COLLECT_INTERVAL = 10  # 秒（dump-counters 约 8 秒刷新一次，10 秒采样可对齐刷新周期，避免过采样产生台阶感）

# 采集到的 Suricata 累计计数器（模块级，跨轮次求增量）
_prev_kernel_drops = None
_prev_decoder_bytes = None
# 计数器"上次真正变化"的时刻，用于按实际经过时间计算速率
_last_change_ts = None
# 上一轮算出的速率，用于计数器未刷新时沿用（避免曲线出现 0 锯齿）
_last_traffic_mbps = 0.0
_prev_cpu_warmup_done = False


def _exec_in_suricata(cmd: list, timeout: int = 20) -> tuple:
    """通过 Docker Engine API 在 suricata 容器内执行命令。

    Returns:
        (exit_code, output) — exit_code=-1 表示执行失败
    """
    try:
        with httpx.Client(transport=httpx.HTTPTransport(uds=DOCKER_SOCK), timeout=timeout) as client:
            resp = client.post(
                f"http://docker/containers/{SURICATA_CONTAINER}/exec",
                json={"AttachStdout": True, "AttachStderr": True, "Cmd": cmd},
            )
            if resp.status_code != 201:
                logger.debug("创建 exec 失败 HTTP %d", resp.status_code)
                return -1, ""
            exec_id = resp.json().get("Id")
            if not exec_id:
                return -1, ""

            resp = client.post(
                f"http://docker/exec/{exec_id}/start",
                json={"Detach": False, "Tty": False},
            )
            if resp.status_code != 200:
                logger.debug("启动 exec 失败 HTTP %d", resp.status_code)
                return -1, ""

            output = _parse_docker_stream(resp.content if hasattr(resp, "content") else b"")

            resp = client.get(f"http://docker/exec/{exec_id}/json")
            exit_code = resp.json().get("ExitCode", -1) if resp.status_code == 200 else -1
            return exit_code, output
    except Exception as e:
        logger.debug("Docker exec 异常: %s", e)
        return -1, ""


def _parse_docker_stream(raw: bytes) -> str:
    """解析 Docker exec 的多路复用流（8 字节头 + payload）。"""
    out = b""
    i = 0
    while i + 8 <= len(raw):
        size = int.from_bytes(raw[i + 4:i + 8], "big")
        if size <= 0:
            break
        out += raw[i + 8:i + 8 + size]
        i += 8 + size
    return out.decode("utf-8", "ignore")


def _fetch_suricata_counters() -> dict | None:
    """取 suricata dump-counters，返回 {kernel_drops, decoder_bytes}；失败返回 None。"""
    exit_code, output = _exec_in_suricata(["suricatasc", "-c", "dump-counters"])
    if exit_code != 0 or not output:
        return None
    try:
        start = output.find("{")
        if start < 0:
            return None
        data = json.loads(output[start:])
        msg = data.get("message", {})
        return {
            "kernel_drops": msg.get("capture", {}).get("kernel_drops", 0),
            "decoder_bytes": msg.get("decoder", {}).get("bytes", 0),
        }
    except Exception as e:
        logger.debug("解析 dump-counters 失败: %s", e)
        return None


def collect_once() -> bool:
    """执行一次采集并落库。返回是否成功。"""
    global _prev_kernel_drops, _prev_decoder_bytes, _prev_cpu_warmup_done
    global _last_change_ts, _last_traffic_mbps

    # 1. CPU / 内存（容器内 psutil 读到的是宿主机资源：无 mem_limit、/proc 共享）
    if not _prev_cpu_warmup_done:
        psutil.cpu_percent(interval=None)  # 预热，首次返回 0.0
        _prev_cpu_warmup_done = True
        return False
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent

    # 2. Suricata 计数
    # 注意：suricata 的 dump-counters 返回的是"周期性刷新的快照"（约 8 秒刷新一次），
    # 不是实时值——5 秒采样时会连续两次拿到完全相同的累计值。
    # 因此采用滑动窗口：只在计数器真正变化时才算增量，并按"实际经过时间"折算速率；
    # 计数器未刷新时沿用上一轮速率（避免曲线出现 0 锯齿），丢包则记 0（增量会在下次刷新时一并计入）。
    c = _fetch_suricata_counters()
    traffic_mbps = _last_traffic_mbps
    drops_delta = 0
    if c:
        drops_now = c["kernel_drops"]
        bytes_now = c["decoder_bytes"]
        now_ts = time.time()

        if _prev_decoder_bytes is None or _prev_kernel_drops is None:
            # 首次：仅建立基线，不产生产量
            _prev_kernel_drops = drops_now
            _prev_decoder_bytes = bytes_now
            _last_change_ts = now_ts
        elif bytes_now > _prev_decoder_bytes:
            # 计数器已刷新：按实际经过时间折算速率
            elapsed = max(now_ts - (_last_change_ts or now_ts), 1.0)
            delta_bytes = bytes_now - _prev_decoder_bytes
            traffic_mbps = round(delta_bytes * 8 / elapsed / 1e6, 1)
            drops_delta = max(drops_now - _prev_kernel_drops, 0)
            _prev_kernel_drops = drops_now
            _prev_decoder_bytes = bytes_now
            _last_change_ts = now_ts
            _last_traffic_mbps = traffic_mbps
        # else: 计数器未刷新（或 suricata 重启导致回退），沿用上次速率、丢包记 0

    # 3. 落库
    try:
        with SessionLocal() as db:
            db.add(SystemMetric(
                cpu_percent=round(cpu, 1),
                memory_percent=round(mem, 1),
                traffic_mbps=traffic_mbps,
                drops_delta=drops_delta,
            ))
            db.commit()
        return True
    except Exception as e:
        logger.error("写入 system_metrics 失败: %s", e)
        return False


def run_forever(stop_event: threading.Event | None = None) -> None:
    """5 秒循环采集（阻塞，应在独立线程中运行）。"""
    logger.info("系统资源采集器启动，间隔 %d 秒", COLLECT_INTERVAL)
    while True:
        if stop_event is not None and stop_event.is_set():
            logger.info("系统资源采集器停止")
            break
        try:
            collect_once()
        except Exception as e:
            logger.error("采集异常: %s", e, exc_info=True)
        time.sleep(COLLECT_INTERVAL)


def start_collector() -> threading.Thread:
    """启动后台采集线程（daemon，随主进程退出）。"""
    t = threading.Thread(target=run_forever, daemon=True, name="metric-collector")
    t.start()
    return t
