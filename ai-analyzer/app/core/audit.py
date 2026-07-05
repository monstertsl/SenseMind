"""审计日志写入辅助"""

from sqlalchemy.orm import Session
from ..db_models.audit_log import LoginLog, SystemLog


def write_login_log(db: Session, *, username: str, success: bool,
                    ip_address: str = "", user_agent: str = "", message: str = "") -> None:
    entry = LoginLog(
        username=username,
        success=success,
        ip_address=ip_address,
        user_agent=user_agent,
        message=message,
    )
    db.add(entry)
    db.commit()


def write_system_log(db: Session, *, action: str, target_type: str,
                     target_id: str = "", detail: str = "",
                     operator: str = "", ip_address: str = "") -> None:
    entry = SystemLog(
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
        operator=operator,
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()
