"""系统配置表（单行记录，id 固定为 1）"""

from datetime import datetime
from sqlalchemy import String, Integer, DateTime, Text, Float
from sqlalchemy.orm import Mapped, mapped_column
from ..core.database import Base


class SystemConfig(Base):
    __tablename__ = "system_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False, default=1)

    # 存储优化
    es_retention_days: Mapped[int] = mapped_column(Integer, default=180, nullable=False)
    raw_log_retention_days: Mapped[int] = mapped_column(Integer, default=7, nullable=False)
    audit_log_retention_days: Mapped[int] = mapped_column(Integer, default=180, nullable=False)

    # 安全策略
    login_fail_limit: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    inactive_days_limit: Mapped[int] = mapped_column(Integer, default=90, nullable=False)
    idle_timeout_minutes: Mapped[int] = mapped_column(Integer, default=30, nullable=False)

    # 允许登录 IP 白名单（逗号分隔，空字符串=全部允许）
    allowed_login_ips: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # LLM 配置（通过系统设置页面配置）
    llm_api_endpoint: Mapped[str] = mapped_column(Text, default="", nullable=False)
    llm_api_key: Mapped[str] = mapped_column(Text, default="", nullable=False)
    llm_model: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    llm_temperature: Mapped[float] = mapped_column(Float, default=0.1, nullable=False)
    llm_max_tokens: Mapped[int] = mapped_column(Integer, default=4000, nullable=False)
    llm_timeout: Mapped[int] = mapped_column(Integer, default=60, nullable=False)

    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
