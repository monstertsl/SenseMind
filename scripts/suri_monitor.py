#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""流量探针长期监控采样（排错脚本，不参与主体服务部署）

用法:  python3 suri_monitor.py -i <接口> [采样间隔秒] [输出目录]
       -i/--iface  监听接口，必填，与部署时指定的接口一致（也可用环境变量 SURI_IFACE）
       采样间隔默认 120s；输出目录默认 /tmp/sensemind-monitor/（或环境变量 SURI_MONITOR_OUT）
输出:  suri_monitor.csv（中文表头，北京时间，追加写）
      suri_monitor.md（同内容的 Markdown 表格，供 VSCode 直接预览）

字段: kernel_drops_delta / wrong_thread_delta / reassembly_gap_delta / ins_*_fail_delta 为窗口增量，
      pps / mbps 按计数器实际变化时间折算。

注意: dump-counters 约 8 秒才刷新一次，两次采样可能读到相同累计值，此时速率沿用上次值、增量记 0。
"""

import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone

CST = timezone(timedelta(hours=8))
DEFAULT_OUT_DIR = "/tmp/sensemind-monitor"
CSV = os.path.join(DEFAULT_OUT_DIR, "suri_monitor.csv")
MD = os.path.join(DEFAULT_OUT_DIR, "suri_monitor.md")
HEADER = (
    "时间,运行时长(s),累计包数(kernel_packets),丢包增量(kernel_drops),"
    "错线程增量(wrong_thread),重组gap增量(reassembly_gap),"
    "重组插入失败(ins_normal_fail),重叠插入失败(ins_overlap_fail),"
    "每秒包数(pps),流量(Mbps),上游端口丢弃(port.rx_discards),"
    "网卡缓冲溢出丢失(rx_missed),网卡丢包(rx_dropped),CPU(%),内存(%),已用内存MB"
)

# tcp.pkt_on_wrong_thread / reassembly_gap / insert_data_*_fail 的路径
PATHS = {
    "kernel_packets": "capture.kernel_packets",
    "kernel_drops": "capture.kernel_drops",
    "decoder_bytes": "decoder.bytes",
    "wrong_thread": "tcp.pkt_on_wrong_thread",
    "reassembly_gap": "tcp.reassembly_gap",
    "ins_normal_fail": "tcp.insert_data_normal_fail",
    "ins_overlap_fail": "tcp.insert_data_overlap_fail",
}
DELTA_KEYS = [
    "kernel_drops",
    "wrong_thread",
    "reassembly_gap",
    "ins_normal_fail",
    "ins_overlap_fail",
]


def sh(cmd, timeout=30):
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout or ""
    except Exception:
        return ""


def dump_counters():
    """返回 dump-counters 的 message 字典；失败返回 None"""
    out = sh('sudo docker exec suricata suricatasc -c "dump-counters"')
    if not out.strip():
        return None
    try:
        msg = json.loads(out)["message"]
        if isinstance(msg, list):
            msg = msg[0]
        return msg if isinstance(msg, dict) else None
    except Exception:
        return None


def g(d, path, default=0):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
        if cur is None:
            return default
    return cur if isinstance(cur, (int, float)) else default


def container_uptime():
    out = sh("sudo docker inspect -f '{{.State.StartedAt}}' suricata").strip()
    if not out:
        return ""
    try:
        # 形如 2026-09-08T14:30:00.123456789Z
        s = out.split(".")[0].replace("Z", "")
        t = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        return str(int((datetime.now(timezone.utc) - t).total_seconds()))
    except Exception:
        return ""


def ethtool_stats(iface):
    """硬件层计数：上游端口丢弃 / RX ring miss / 网卡丢包
    注意: ethtool -S 里上游端口字段写作 port.rx_discards（点号），与 CSV 表头的
    port_rx_discards（下划线）不同，这里做映射。
    """
    mapping = {
        "port.rx_discards": "port_rx_discards",
        "rx_missed_errors": "rx_missed_errors",
        "rx_dropped": "rx_dropped",
    }
    res = {v: "" for v in mapping.values()}
    out = sh("sudo ethtool -S %s" % iface)
    for line in out.splitlines():
        line = line.strip().lower()
        for k, csv_key in mapping.items():
            if line.startswith(k + ":"):
                res[csv_key] = line.split(":", 1)[1].strip()
    return res


def cpu_percent():
    """读 /proc/stat，间隔 0.4s 取两次差值算 CPU 利用率（无第三方依赖）"""
    def read():
        with open("/proc/stat") as f:
            parts = [float(x) for x in f.readline().split()[1:]]
        idle = parts[3] + (parts[4] if len(parts) > 4 else 0.0)
        return sum(parts), idle

    try:
        t0, i0 = read()
        time.sleep(0.4)
        t1, i1 = read()
        dt = t1 - t0
        di = i1 - i0
        if dt <= 0:
            return ""
        return "%.1f" % (100.0 * (1 - di / dt))
    except Exception:
        return ""


def mem_stats():
    """返回 (used_mb, total_mb, percent)"""
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                info[k] = int(v.split()[0])  # kB
        total = info["MemTotal"] / 1024.0
        avail = info.get("MemAvailable", 0) / 1024.0
        used = max(total - avail, 0.0)
        return "%.0f" % used, "%.0f" % total, "%.1f" % (100.0 * used / total if total else 0)
    except Exception:
        return "", "", ""


def sync_md():
    """把 CSV 全量转成 Markdown 表格，供 VSCode 直接预览"""
    try:
        with open(CSV, encoding="utf-8") as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]
    except OSError:
        return
    if not lines:
        return
    with open(MD, "w", encoding="utf-8") as f:
        f.write("| " + " | ".join(lines[0].split(",")) + " |\n")
        f.write("|" + "|".join(["---"] * len(lines[0].split(","))) + "|\n")
        for l in lines[1:]:
            f.write("| " + " | ".join(l.split(",")) + " |\n")


def main():
    global CSV, MD
    ap = argparse.ArgumentParser(description="流量探针长期监控采样")
    ap.add_argument(
        "-i", "--iface", default=os.environ.get("SURI_IFACE", ""),
        help="监听接口，如 eno1np0（也可用环境变量 SURI_IFACE）",
    )
    ap.add_argument("interval", nargs="?", type=int, default=120, help="采样间隔秒，默认 120")
    ap.add_argument(
        "out_dir", nargs="?",
        default=os.environ.get("SURI_MONITOR_OUT") or DEFAULT_OUT_DIR,
        help="输出目录，默认 %s" % DEFAULT_OUT_DIR,
    )
    args = ap.parse_args()
    if not args.iface:
        ap.error("请用 -i/--iface 指定监听接口（如 -i eno1np0）")

    interval = max(args.interval, 10)
    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)
    CSV = os.path.join(out_dir, "suri_monitor.csv")
    MD = os.path.join(out_dir, "suri_monitor.md")

    if not os.path.exists(CSV):
        with open(CSV, "w", encoding="utf-8") as f:
            f.write(HEADER + "\n")
        sync_md()

    prev_vals = None      # 上次读到的累计值
    prev_mono = None      # 上次"计数器发生变化"的时刻
    last_pps = ""         # 未刷新时沿用的速率
    last_mbps = ""

    while True:
        c = dump_counters()
        now_mono = time.monotonic()
        if c is None:
            time.sleep(interval)
            continue

        cur = {k: g(c, p) for k, p in PATHS.items()}

        if prev_vals is None:
            # 第一帧只建基线，不产生速率/增量
            prev_vals, prev_mono = cur, now_mono
            time.sleep(interval)
            continue

        grew = (
            cur["kernel_packets"] > prev_vals["kernel_packets"]
            and cur["decoder_bytes"] > prev_vals["decoder_bytes"]
        )
        regressed = (
            cur["kernel_packets"] < prev_vals["kernel_packets"]
            or cur["decoder_bytes"] < prev_vals["decoder_bytes"]
        )
        elapsed = now_mono - prev_mono if prev_mono else 0

        if regressed:
            # 计数器回退（Suricata 重启）：重建基线，否则会算出负速率
            prev_vals, prev_mono = cur, now_mono
            deltas = {k: 0 for k in DELTA_KEYS}
        elif grew and elapsed > 0:
            dpkts = cur["kernel_packets"] - prev_vals["kernel_packets"]
            dbytes = cur["decoder_bytes"] - prev_vals["decoder_bytes"]
            pps = dpkts / elapsed
            mbps = dbytes * 8 / elapsed / 1_000_000
            last_pps = "%.0f" % pps
            last_mbps = "%.1f" % mbps
            deltas = {k: max(cur[k] - prev_vals[k], 0) for k in DELTA_KEYS}
            prev_vals, prev_mono = cur, now_mono
        else:
            # 计数器未刷新：沿用上次速率，增量记 0（避免假台阶/假丢包）
            deltas = {k: 0 for k in DELTA_KEYS}

        eth = ethtool_stats(args.iface)
        cpu = cpu_percent()
        used_mb, total_mb, mem_pct = mem_stats()
        ts = datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S")

        row = [
            ts,
            container_uptime(),
            str(cur["kernel_packets"]),
            str(deltas["kernel_drops"]),
            str(deltas["wrong_thread"]),
            str(deltas["reassembly_gap"]),
            str(deltas["ins_normal_fail"]),
            str(deltas["ins_overlap_fail"]),
            last_pps,
            last_mbps,
            str(eth["port_rx_discards"]),
            str(eth["rx_missed_errors"]),
            str(eth["rx_dropped"]),
            cpu,
            mem_pct,
            used_mb,
        ]
        with open(CSV, "a", encoding="utf-8") as f:
            f.write(",".join(row) + "\n")
        sync_md()

        time.sleep(interval)


if __name__ == "__main__":
    main()
