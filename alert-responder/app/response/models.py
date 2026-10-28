"""联动外发数据模型。

5 张表全部由本服务创建；ai-analyzer 只向 response_pending_actions 写入（Percolator 命中），
不建表、不做迁移，避免同一 schema 由两个服务各自管理。
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class ResponseBase(DeclarativeBase):
    pass


class ResponseDevice(ResponseBase):
    __tablename__ = "response_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    driver: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # 记录建单时的脚本清单版本：清单不兼容变更后可标记「需重新填写」
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # 非敏感字段明文，敏感字段值为 enc:... 密文
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    secret_fields: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class ResponseTask(ResponseBase):
    __tablename__ = "response_tasks"
    __table_args__ = (UniqueConstraint("device_id", "preset_id", name="uq_response_tasks_device_preset"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("response_devices.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    preset_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class ResponseWhitelist(ResponseBase):
    __tablename__ = "response_whitelist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    value: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    note: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ResponseBlockRecord(ResponseBase):
    __tablename__ = "response_block_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    device_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # 脱敏后的原始请求/响应，便于事后核对设备侧实际状态
    request_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    event_id: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )


class ResponsePendingAction(ResponseBase):
    """Percolator 命中的待执行事件；analyzer 写入，本服务消费。"""

    __tablename__ = "response_pending_actions"
    __table_args__ = (
        UniqueConstraint("task_id", "device_id", "ip", name="uq_response_pending_task_device_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(Integer, nullable=False)
    device_id: Mapped[int] = mapped_column(Integer, nullable=False)
    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    event_id: Mapped[str] = mapped_column(String(300), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    processed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


TABLES = (
    ResponseDevice.__table__,
    ResponseTask.__table__,
    ResponseWhitelist.__table__,
    ResponseBlockRecord.__table__,
    ResponsePendingAction.__table__,
)

# create_all 不会给已存在的表补列；后续新增字段在此登记幂等 ALTER
_ENSURE_COLUMNS: tuple[str, ...] = ()


def create_response_tables(engine: Engine) -> None:
    ResponseBase.metadata.create_all(engine, tables=list(TABLES))
    if not _ENSURE_COLUMNS:
        return
    with engine.begin() as connection:
        for statement in _ENSURE_COLUMNS:
            connection.exec_driver_sql(statement)
