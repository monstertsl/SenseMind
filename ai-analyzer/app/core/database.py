"""SQLAlchemy 同步数据库连接 + 初始化"""

import os
import logging
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from ..config import Config

logger = logging.getLogger(__name__)


def _build_database_url() -> str:
    env_url = os.environ.get("DATABASE_URL")
    if env_url:
        return env_url
    cfg = Config().redis
    password = os.environ.get("ELASTIC_PASSWORD", "")
    return f"postgresql+psycopg2://postgres:{password}@postgres:5432/sensemind"


engine = create_engine(_build_database_url(), pool_pre_ping=True, pool_size=10, max_overflow=20, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI 依赖：同步 Session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """建表 + 初始化 admin 用户 + 默认系统配置"""
    # 导入模型以注册到 Base.metadata
    from ..db_models.user import User  # noqa
    from ..db_models.system_config import SystemConfig  # noqa
    from ..db_models.audit_log import LoginLog, SystemLog  # noqa
    from .auth import hash_password

    Base.metadata.create_all(bind=engine)

    # 迁移：为已有 system_config 表添加新列（PostgreSQL ADD COLUMN IF NOT EXISTS）
    with engine.connect() as conn:
        conn.execute(text(
            "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS audit_log_retention_days INTEGER NOT NULL DEFAULT 180"
        ))
        # 将旧默认值 30 更新为 180（仅在值仍为旧默认时）
        conn.execute(text(
            "UPDATE system_config SET es_retention_days = 180 WHERE es_retention_days = 30"
        ))
        conn.commit()

    with SessionLocal() as db:
        # 初始化 admin 用户
        existing = db.execute(select(User).where(User.username == "admin")).scalar_one_or_none()
        if not existing:
            admin_pwd = os.environ.get("ELASTIC_PASSWORD", "admin")
            admin = User(
                username="admin",
                password_hash=hash_password(admin_pwd),
                role="admin",
                auth_mode="PASSWORD_ONLY",
                is_active=True,
            )
            db.add(admin)
            db.commit()
            logger.info("已初始化 admin 用户（密码取自 ELASTIC_PASSWORD）")

        # 初始化默认系统配置（单行 id=1）
        cfg = db.execute(select(SystemConfig).where(SystemConfig.id == 1)).scalar_one_or_none()
        if not cfg:
            cfg = SystemConfig(id=1)
            db.add(cfg)
            db.commit()
            logger.info("已初始化默认系统配置")
