"""审计日志写入辅助（统一写入 system_logs）"""

from sqlalchemy.orm import Session
from ..db_models.audit_log import SystemLog


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


def write_login_log(db: Session, *, username: str, success: bool,
                    ip_address: str = "", detail: str = "") -> None:
    """记录登录日志（统一写入 system_logs，action=login）。

    Args:
        success: 登录是否成功
        detail: 登录成败原因（成功时可为空，失败时含原因）
    """
    full_detail = detail or ("登录成功" if success else "登录失败")
    if not success and not detail:
        full_detail = "登录失败"
    entry = SystemLog(
        action="login",
        target_type="auth",
        detail=full_detail,
        operator=username,
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()
