"""系统信息服务 —— CPU / 内存 / 磁盘占用（psutil）"""

import psutil
from pydantic import BaseModel


class SystemInfoData(BaseModel):
    cpu_percent: float
    cpu_count: int
    memory_percent: float
    memory_total: int
    memory_used: int
    disk_percent: float
    disk_total: int
    disk_used: int


class SystemService:
    def get_info(self) -> SystemInfoData:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        cpu_count = psutil.cpu_count(logical=True) or 1
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        return SystemInfoData(
            cpu_percent=round(cpu_percent, 1),
            cpu_count=cpu_count,
            memory_percent=round(mem.percent, 1),
            memory_total=mem.total,
            memory_used=mem.used,
            disk_percent=round(disk.percent, 1),
            disk_total=disk.total,
            disk_used=disk.used,
        )


def get_system_service() -> SystemService:
    return SystemService()
