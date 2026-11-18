"""系统资源时序表：10 秒粒度采集，供监测中心趋势图使用

仅记录趋势图需要的 5 个指标：
  cpu_percent    CPU 使用率
  memory_percent 内存使用率
  traffic_mbps   流量（Mbps，Suricata 抓包面）
  drops_delta    丢包增量（该采样周期内 kernel_drops 的新增包数）
  disk_percent   磁盘使用率（仅探针行填写；中心磁盘为单值快照不经此表）

行归属（probe_id）：
  NULL = 中心自身采集（metric_collector）
  非空 = 探针上报（POST /probe/health 批量时序，probe_id 即 probe_uid）
  保留策略随 audit_log_retention_days（「系统日志保留天数」）按 created_at 全表清理自动覆盖。

注意：
- drops_delta 存的是"增量"而非累计值，查询长时间范围时必须 SUM，
  不要用 AVG（会把集中丢包平均掉而严重低估）。
- 保留天数由 system_config.audit_log_retention_days 控制（默认 180 天）。
"""

from datetime import datetime
from sqlalchemy import BigInteger, Float, Integer, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column
from ..core.database import Base


class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False, index=True
    )
    cpu_percent: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    memory_percent: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    traffic_mbps: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    drops_delta: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # 探针行归属（NULL=中心自身）；查询仪表盘时 WHERE probe_id IS NULL
    probe_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # 数据盘使用率（探针监控 /data；中心磁盘走 system_service 单值快照，此列为 NULL）
    disk_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
