"""探针注册表（双 ID 设计：内部 ID 为系统唯一标识，备注名/站点仅展示用）

需求文档 F16/F9 数据基础。
"""

import json
from datetime import datetime
from sqlalchemy import String, Integer, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from ..core.database import Base


class ProbeRegistry(Base):
    __tablename__ = "probe_registry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # 内部 ID（prb- 前缀 + 短随机码），系统唯一标识，贯穿证书/事件/配置/吊销全链路，永不改变
    probe_uid: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)

    # 备注名 / 站点（纯展示层，可随时修改，不影响历史数据）
    name: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    site: Mapped[str] = mapped_column(String(100), default="", nullable=False)

    # 状态：pending=待注册（token 已签发）/ active=已注册 / revoked=已吊销
    # 注册表条目永不自动删除，彻底删除仅管理员手动操作（F14）
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)

    # 一次性 token（仅存 SHA256 哈希；24h 有效；Web 一次性展示）
    token_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    token_expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    token_used_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # 注册信息
    registered_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    registered_ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)

    # 当前客户端证书（续签/覆盖签发时更新）
    cert_serial: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    cert_not_after: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    # 已吊销的旧证书序列号（JSON 数组；重装覆盖签发时旧证书加入此处，续签接口拒绝这些序列号）
    revoked_cert_serials: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # 健康上报（最近一次，JSON：cpu/mem/disk/流量/丢包等，F7）
    last_report_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    last_health: Mapped[str] = mapped_column(Text, default="", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def revoked_serials(self) -> list:
        try:
            return json.loads(self.revoked_cert_serials) if self.revoked_cert_serials else []
        except (ValueError, TypeError):
            return []

    def add_revoked_serial(self, serial: str) -> None:
        serials = self.revoked_serials()
        if serial and serial not in serials:
            serials.append(serial)
            self.revoked_cert_serials = json.dumps(serials)
