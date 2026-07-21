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
    from ..db_models.audit_log import SystemLog  # noqa
    from ..db_models.ai_bypass_rule import AiBypassRule  # noqa
    from .auth import hash_password

    Base.metadata.create_all(bind=engine)

    # 迁移：为已存在的 ai_bypass_rules 表补充 host 字段（幂等，仅对已建表生效）
    try:
        with engine.begin() as conn:
            conn.execute(text(
                "ALTER TABLE ai_bypass_rules ADD COLUMN IF NOT EXISTS host VARCHAR(255) NOT NULL DEFAULT ''"
            ))
    except Exception as e:  # noqa: BLE001
        logger.warning("ai_bypass_rules.host 字段迁移失败（首次建表会自动包含，可忽略）: %s", e)

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
