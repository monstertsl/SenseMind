"""系统信息服务 —— 磁盘占用（psutil）

CPU / 内存已由 metric_collector 按时序采集落库，此服务仅保留磁盘单值快照，
供监测中心「磁盘使用率」仪表盘使用。
"""

import psutil
from pydantic import BaseModel


class SystemInfoData(BaseModel):
    disk_percent: float
    disk_total: int
    disk_used: int


class SystemService:
    def get_info(self) -> SystemInfoData:
        disk = psutil.disk_usage("/")
        return SystemInfoData(
            disk_percent=round(disk.percent, 1),
            disk_total=disk.total,
            disk_used=disk.used,
        )


def get_system_service() -> SystemService:
    return SystemService()
