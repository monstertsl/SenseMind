"""AI 分析白名单规则模型"""

from datetime import datetime
from sqlalchemy import String, Integer, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from ..core.database import Base


class AiBypassRule(Base):
    __tablename__ = "ai_bypass_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, default="")
    src_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False, default="")
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    remark: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
