"""系统资源时序查询 —— 按档位聚合，供监测中心趋势图使用

档位与聚合策略（5 秒原始数据）：
  1h  → 不聚合，返回原始点（720 点，保留 5 秒精度，用于排查瞬时微突发）
  24h → 2 分钟桶（720 点）
  7d  → 30 分钟桶（336 点）

聚合函数：
  cpu_percent / memory_percent / traffic_mbps → AVG
  drops_delta                                  → SUM（必须！）

丢包为何必须 SUM：
  drops_delta 存的是"每 5 秒的丢包增量"，是事件累计量而非瞬时状态。
  例如某 2 分钟桶内 24 个采样点中一个丢了 38 万包，SUM 得真实总量 38 万，
  AVG 会算成 1.6 万而严重低估，MAX 会漏掉同桶内的多次小丢包。
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import BigInteger, func, select

from ..core.database import SessionLocal
from ..db_models.system_metric import SystemMetric

logger = logging.getLogger(__name__)

_SHANGHAI_TZ = timezone(timedelta(hours=8))

# 档位 → (跨度秒数, 桶大小秒数)；桶大小 0 表示不聚合
# 方案 A：各档位点数接近（约 300+ 点），视觉密度一致
RANGES = {
    "1h": (3600, 10),       # 10 秒桶 → 360 点
    "24h": (86400, 240),    # 4 分钟桶 → 360 点
    "7d": (604800, 1800),   # 30 分钟桶 → 336 点
}


def query_metrics(range_key: str = "24h") -> dict:
    """按档位查询聚合后的时序数据。

    Args:
        range_key: "1h" | "24h" | "7d"

    Returns:
        {
          "range": "24h",
          "bucket_seconds": 120,
          "points": [
            {"ts": "2026-08-28T14:30:00+08:00",
             "cpu_percent": 12.4, "memory_percent": 38.8,
             "traffic_mbps": 934.9, "drops": 387312},
            ...
          ]
        }
    """
    if range_key not in RANGES:
        range_key = "24h"
    span_seconds, bucket = RANGES[range_key]

    # 注意：created_at 由 SQLAlchemy default=datetime.utcnow 写入，是【UTC naive】。
    # 查询起点必须用 UTC 保持一致，否则北京时间会比 UTC 快 8 小时导致范围偏移查不到数据。
    # （展示时区转换统一在 _iso() 里做）
    now = datetime.utcnow()
    start = now - timedelta(seconds=span_seconds)

    with SessionLocal() as db:
        if bucket == 0:
            # 不聚合：直接取原始点
            rows = db.execute(
                select(
                    SystemMetric.created_at,
                    SystemMetric.cpu_percent,
                    SystemMetric.memory_percent,
                    SystemMetric.traffic_mbps,
                    SystemMetric.drops_delta,
                )
                .where(SystemMetric.created_at >= start)
                .order_by(SystemMetric.created_at.asc())
            ).all()
            points = [
                {
                    "ts": _iso(r[0]),
                    "cpu_percent": round(r[1] or 0.0, 1),
                    "memory_percent": round(r[2] or 0.0, 1),
                    "traffic_mbps": round(r[3] or 0.0, 1),
                    "drops": int(r[4] or 0),
                }
                for r in rows
            ]
        else:
            # 按固定时间桶聚合（Postgres）：
            # EXTRACT(EPOCH FROM created_at) 取整 → 整除桶大小 → 对齐桶边界。
            # 注意：SQLAlchemy 会把 bucket(int) 转成 NUMERIC，导致 BIGINT/NUMERIC 返回
            # 带小数、整除对齐失效（每个点各成一组）。必须对除法结果显式 cast 回整数
            # （cast 会截断小数，等效 floor）。
            ts_sec = func.cast(func.extract("epoch", SystemMetric.created_at), BigInteger)
            bucket_expr = func.cast(ts_sec / bucket, BigInteger) * bucket

            rows = db.execute(
                select(
                    bucket_expr.label("bkt"),
                    func.avg(SystemMetric.cpu_percent),
                    func.avg(SystemMetric.memory_percent),
                    func.avg(SystemMetric.traffic_mbps),
                    func.sum(SystemMetric.drops_delta),  # 丢包必须 SUM
                )
                .where(SystemMetric.created_at >= start)
                .group_by("bkt")
                .order_by("bkt")
            ).all()
            points = [
                {
                    "ts": _iso(datetime.fromtimestamp(int(r[0]), tz=_SHANGHAI_TZ)),
                    "cpu_percent": round(float(r[1] or 0), 1),
                    "memory_percent": round(float(r[2] or 0), 1),
                    "traffic_mbps": round(float(r[3] or 0), 1),
                    "drops": int(r[4] or 0),
                }
                for r in rows
            ]

    return {
        "range": range_key,
        "bucket_seconds": bucket,
        "points": points,
    }


def _iso(dt: datetime) -> str:
    """统一输出带 +08:00 时区的 ISO 时间（入库是 UTC，展示按北京时间）。"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_SHANGHAI_TZ).isoformat()
