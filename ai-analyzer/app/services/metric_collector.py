"""系统资源时序采集器 —— 10 秒粒度，写入 system_metrics 表

设计要点：
- 独立于 system_service.py（后者服务仪表盘实时快照 API，两者互不影响）。
- 采集逻辑统一在 metrics_common.py（与探针 probe-agent 共用同一份代码，
  流量/丢包同口径=Suricata 抓包面，曲线可直接对比），本文件只负责
  调度（10 秒循环）、Suricata 计数器对齐（10s 采样对齐 8s 刷新周期）
  与落库（PG system_metrics）。
- 流量与丢包均按"增量"计算（相邻两次采样的差值），落库即增量值。
  查询长时间范围时丢包必须 SUM（增量可加）；用 AVG 会严重低估集中丢包。
"""

import logging
import threading
import time

from ..core.database import SessionLocal
from ..db_models.system_metric import SystemMetric
from .metrics_common import SuricataCounterWindow, collect_cpu_percent, collect_memory_percent, warmup_cpu

logger = logging.getLogger(__name__)

SURICATA_CONTAINER = "suricata"
COLLECT_INTERVAL = 10  # 秒（dump-counters 约 8 秒刷新一次，10 秒采样可对齐刷新周期，避免过采样产生台阶感）

# Suricata 计数器滑动窗口（模块级，跨轮次求增量）
_window = SuricataCounterWindow(SURICATA_CONTAINER)
_cpu_warmup_done = False


def collect_once() -> bool:
    """执行一次采集并落库。返回是否成功。"""
    global _cpu_warmup_done

    # 1. CPU / 内存（容器内 psutil 读到的是宿主机资源：无 mem_limit、/proc 共享）
    if not _cpu_warmup_done:
        warmup_cpu()  # 预热，首次返回 0.0
        _cpu_warmup_done = True
        return False
    cpu = collect_cpu_percent()
    mem = collect_memory_percent()

    # 2. Suricata 计数（滑动窗口：未刷新沿用上次速率、丢包记 0）
    traffic_mbps = 0.0
    drops_delta = 0
    feed = _window.feed()
    if feed is not None:
        traffic_mbps, drops_delta = feed

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
    """10 秒循环采集（阻塞，应在独立线程中运行）。"""
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
