"""分析中心检索快捷方式模型

保存用户在分析中心使用的一组筛选条件，供「快捷检索」一键复用。
字段设计为后续告警联动预留：filters 与 AlertQueryParams 的筛选参数同名，
联动模块可直接用其构造查询做命中匹配；is_enabled / extra 用于启停与联动动作配置。
"""

from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from ..core.database import Base


class AlertSearchPreset(Base):
    __tablename__ = "alert_search_presets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # 快捷方式名称，全局唯一，便于作为联动规则的引用标识
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    remark: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    # JSON 文本：筛选条件，键名与 AlertQueryParams 的筛选参数一致
    filters: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    # 是否启用（预留：告警联动可据此启停该快捷方式对应的动作）
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # 预留：后续告警联动的动作配置（邮件通知 / 防火墙阻断等），JSON 文本
    extra: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
