"""系统资源时序表：5 秒粒度采集，供监测中心趋势图使用

仅记录趋势图需要的 4 个指标：
  cpu_percent    CPU 使用率
  memory_percent 内存使用率
  traffic_mbps   流量（Mbps）
  drops_delta    丢包增量（该采样周期内 kernel_drops 的新增包数）

注意：
- drops_delta 存的是"增量"而非累计值，查询长时间范围时必须 SUM，
  不要用 AVG（会把集中丢包平均掉而严重低估）。
- 保留天数由 system_config.metric_retention_days 控制（默认 30 天）。
"""

from datetime import datetime
from sqlalchemy import BigInteger, Float, Integer, DateTime
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
