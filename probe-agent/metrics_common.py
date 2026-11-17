"""共享健康采集模块 —— 中心 metric_collector 与探针 probe-agent 共用

⚠️ 同步义务：本文件同时被中心（ai-analyzer 容器）与探针（probe-agent 容器）使用。
探针侧构建时 COPY 本文件进 probe-agent 镜像；修改本文件后必须同步更新两处
（中心随 ai-analyzer 重建生效，探针随部署包更新生效），并在文档变更记录注明。

设计要点（与 metric_collector 一致）：
- CPU 用 psutil.cpu_percent(interval=None) 非阻塞（首次调用返回 0.0，需先预热）
- Suricata 计数经 Docker Engine API（unix socket）在容器内执行 dump-counters，
  无需 docker CLI/SDK；容器为"周期性刷新的快照"（约 8 秒刷新一次），
  因此用滑动窗口：只在计数器真正变化时算增量，并按实际经过时间折算速率；
  计数器未刷新时沿用上一轮速率（避免曲线 0 锯齿），丢包记 0（增量下次一并计入）。
- 流量口径 = Suricata 抓包面（decoder.bytes，Mbps）；丢包口径 = capture.kernel_drops。
  中心与探针使用同一口径，曲线可直接对比；丢包是漏报风险指标（抓包环丢弃=漏检）。
"""

import json
import logging
import time

import httpx
import psutil

logger = logging.getLogger(__name__)

DOCKER_SOCK = "/var/run/docker.sock"


def collect_cpu_percent() -> float:
    """CPU 使用率（需先调用一次 warmup_cpu，否则首轮为 0.0）。"""
    return psutil.cpu_percent(interval=None)


def warmup_cpu() -> None:
    """psutil cpu_percent 预热：首次调用返回 0.0，丢掉。"""
    psutil.cpu_percent(interval=None)


def collect_memory_percent() -> float:
    """内存使用率（容器内 psutil 读宿主机 /proc：无 mem_limit 时 /proc 共享）。"""
    return psutil.virtual_memory().percent


def collect_disk_percent(path: str = "/") -> float:
    """磁盘使用率。中心监控 /（系统盘）；探针监控 /data（数据分区）。"""
    return psutil.disk_usage(path).percent


def collect_disk_usage(path: str = "/") -> tuple:
    """磁盘 (percent, used_bytes, total_bytes)，供探针健康上报携带容量信息。"""
    u = psutil.disk_usage(path)
    return u.percent, u.used, u.total


def _exec_in_container(container: str, cmd: list, timeout: int = 20) -> tuple:
    """通过 Docker Engine API 在指定容器内执行命令。

    Returns:
        (exit_code, output) — exit_code=-1 表示执行失败
    """
    try:
        with httpx.Client(transport=httpx.HTTPTransport(uds=DOCKER_SOCK), timeout=timeout) as client:
            resp = client.post(
                f"http://docker/containers/{container}/exec",
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


class SuricataCounterWindow:
    """Suricata dump-counters 滑动窗口：流量 Mbps + 丢包增量。

    封装 metric_collector 原有的全局状态机（计数器回退重建基线、
    未刷新沿用上次速率、按实际经过时间折算速率），中心与探针共用。
    """

    def __init__(self, container: str):
        self.container = container
        self._prev_kernel_drops: int | None = None
        self._prev_decoder_bytes: int | None = None
        self._last_change_ts: float | None = None
        self._last_traffic_mbps = 0.0

    def _fetch_counters(self) -> dict | None:
        """取 dump-counters，返回 {kernel_drops, decoder_bytes}；失败返回 None。"""
        exit_code, output = _exec_in_container(self.container, ["suricatasc", "-c", "dump-counters"])
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

    def feed(self) -> tuple[float, int] | None:
        """取一次计数器并推进滑动窗口。

        Returns:
            (traffic_mbps, drops_delta)；取不到计数器返回 None（语义：
            流量沿用上次值、丢包记 0，由调用方处理）。
        """
        c = self._fetch_counters()
        if not c:
            return None

        drops_now = c["kernel_drops"]
        bytes_now = c["decoder_bytes"]
        now_ts = time.time()
        traffic_mbps = self._last_traffic_mbps
        drops_delta = 0

        if self._prev_decoder_bytes is None or self._prev_kernel_drops is None:
            # 首次：仅建立基线，不产生增量
            self._prev_kernel_drops = drops_now
            self._prev_decoder_bytes = bytes_now
            self._last_change_ts = now_ts
        elif bytes_now < self._prev_decoder_bytes or drops_now < self._prev_kernel_drops:
            logger.warning(
                "Suricata 计数器回退，重建基线: bytes %s->%s, drops %s->%s",
                self._prev_decoder_bytes, bytes_now, self._prev_kernel_drops, drops_now,
            )
            self._prev_kernel_drops = drops_now
            self._prev_decoder_bytes = bytes_now
            self._last_change_ts = now_ts
        elif bytes_now > self._prev_decoder_bytes:
            # 计数器已刷新：按实际经过时间折算速率
            elapsed = max(now_ts - (self._last_change_ts or now_ts), 1.0)
            delta_bytes = bytes_now - self._prev_decoder_bytes
            traffic_mbps = round(delta_bytes * 8 / elapsed / 1e6, 1)
            drops_delta = max(drops_now - self._prev_kernel_drops, 0)
            self._prev_kernel_drops = drops_now
            self._prev_decoder_bytes = bytes_now
            self._last_change_ts = now_ts
            self._last_traffic_mbps = traffic_mbps
        # else: 计数器未刷新（或容器重启导致回退），沿用上次速率、丢包记 0

        return traffic_mbps, drops_delta
