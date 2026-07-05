"""用户管理路由"""

import uuid
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from typing import Optional

from ..core.database import get_db
from ..core.auth import (
    hash_password, verify_password, generate_totp_secret, get_totp_uri, verify_totp,
    get_current_user, require_role, AuthContext,
)
from ..core.security import encrypt_data, decrypt_data
from ..core.audit import write_system_log
from ..core.rate_limit import invalidate_user_status
from ..db_models.user import User
from ..schemas import ApiResponse

router = APIRouter(prefix="/api/v1/users", tags=["用户管理"])


class UserCreate(BaseModel):
    username: str
    password: Optional[str] = None
    role: str = "user"
    auth_mode: str = "PASSWORD_ONLY"
    is_active: bool = True


class UserUpdate(BaseModel):
    role: Optional[str] = None
    auth_mode: Optional[str] = None
    is_active: Optional[bool] = None


class PasswordUpdate(BaseModel):
    old_password: str
    new_password: str


class AdminPasswordReset(BaseModel):
    new_password: str


class TOTPVerifyRequest(BaseModel):
    code: Optional[str] = None  # 管理员操作时可空


def _user_to_dict(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "auth_mode": user.auth_mode,
        "is_active": user.is_active,
        "failed_login_attempts": user.failed_login_attempts,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "totp_enabled": bool(user.totp_secret_encrypted),
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


def _client_ip(request: Request) -> str:
    return (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or request.headers.get("x-real-ip", "")
        or (request.client.host if request.client else "")
    )


@router.get("")
def list_users(db: Session = Depends(get_db), current_user: AuthContext = Depends(require_role("admin"))):
    users = db.execute(select(User).order_by(User.created_at.desc())).scalars().all()
    return ApiResponse(code=0, message="ok", data=[_user_to_dict(u) for u in users], request_id=str(uuid.uuid4()))


@router.get("/me")
def get_me(current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.execute(select(User).where(User.id == current_user.user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    data = _user_to_dict(user)
    # 普通用户隐藏失败次数
    if current_user.role != "admin":
        data["failed_login_attempts"] = 0
    return ApiResponse(code=0, message="ok", data=data, request_id=str(uuid.uuid4()))


@router.post("")
def create_user(body: UserCreate, request: Request, db: Session = Depends(get_db),
                current_user: AuthContext = Depends(require_role("admin"))):
    if db.execute(select(User).where(User.username == body.username)).scalar_one_or_none():
        raise HTTPException(status_code=400, detail="用户名已存在")

    if body.auth_mode == "TOTP_ONLY":
        password_hash = hash_password(secrets.token_hex(32))
    else:
        if not body.password:
            raise HTTPException(status_code=400, detail="该认证模式需要密码")
        if len(body.password) < 8:
            raise HTTPException(status_code=400, detail="密码至少 8 位")
        password_hash = hash_password(body.password)

    user = User(
        username=body.username,
        password_hash=password_hash,
        role=body.role,
        auth_mode=body.auth_mode,
        is_active=body.is_active,
    )
    if body.auth_mode in ("TOTP_ONLY", "PASSWORD_AND_TOTP"):
        secret = generate_totp_secret()
        user.totp_secret_encrypted = encrypt_data(secret)

    db.add(user)
    db.commit()
    db.refresh(user)

    write_system_log(db, action="create", target_type="user", target_id=str(user.id),
                     detail=f"创建用户 {user.username}，角色 {user.role}，认证方式 {user.auth_mode}",
                     operator=current_user.username, ip_address=_client_ip(request))

    return ApiResponse(code=0, message="ok", data=_user_to_dict(user), request_id=str(uuid.uuid4()))


@router.patch("/{user_id}")
def update_user(user_id: int, body: UserUpdate, request: Request, db: Session = Depends(get_db),
                current_user: AuthContext = Depends(require_role("admin"))):
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    changes = []
    if body.role is not None:
        changes.append(f"角色: {user.role} → {body.role}")
        user.role = body.role
    if body.auth_mode is not None:
        changes.append(f"认证方式: {user.auth_mode} → {body.auth_mode}")
        user.auth_mode = body.auth_mode
    if body.is_active is not None:
        changes.append(f"状态: {'启用' if body.is_active else '禁用'}")
        user.is_active = body.is_active
    db.commit()
    db.refresh(user)
    invalidate_user_status(user_id)

    if changes:
        write_system_log(db, action="update", target_type="user", target_id=str(user_id),
                         detail=f"修改用户 {user.username}：{'，'.join(changes)}",
                         operator=current_user.username, ip_address=_client_ip(request))

    return ApiResponse(code=0, message="ok", data=_user_to_dict(user), request_id=str(uuid.uuid4()))


@router.delete("/{user_id}")
def delete_user(user_id: int, request: Request, db: Session = Depends(get_db),
                current_user: AuthContext = Depends(require_role("admin"))):
    if user_id == current_user.user_id:
        raise HTTPException(status_code=400, detail="不能删除自己")
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    username = user.username
    db.delete(user)
    db.commit()
    invalidate_user_status(user_id)
    write_system_log(db, action="delete", target_type="user", target_id=str(user_id),
                     detail=f"删除用户 {username}",
                     operator=current_user.username, ip_address=_client_ip(request))
    return ApiResponse(code=0, message="ok", data={"message": "已删除"}, request_id=str(uuid.uuid4()))


@router.post("/{user_id}/password")
def change_password(user_id: int, body: PasswordUpdate, db: Session = Depends(get_db),
                    current_user: AuthContext = Depends(get_current_user)):
    if current_user.user_id != user_id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="无权修改他人密码")
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not verify_password(body.old_password, user.password_hash):
        raise HTTPException(status_code=400, detail="原密码错误")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="新密码至少 8 位")
    user.password_hash = hash_password(body.new_password)
    db.commit()
    invalidate_user_status(user_id)
    return ApiResponse(code=0, message="ok", data={"message": "密码已修改"}, request_id=str(uuid.uuid4()))


@router.put("/{user_id}/password/reset")
def admin_reset_password(user_id: int, body: AdminPasswordReset, request: Request, db: Session = Depends(get_db),
                         current_user: AuthContext = Depends(require_role("admin"))):
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="新密码至少 8 位")
    user.password_hash = hash_password(body.new_password)
    db.commit()
    invalidate_user_status(user_id)
    write_system_log(db, action="reset_password", target_type="user", target_id=str(user_id),
                     detail=f"重置用户 {user.username} 的密码",
                     operator=current_user.username, ip_address=_client_ip(request))
    return ApiResponse(code=0, message="ok", data={"message": "密码已重置"}, request_id=str(uuid.uuid4()))


@router.post("/{user_id}/totp/enable")
def enable_totp(user_id: int, db: Session = Depends(get_db),
                current_user: AuthContext = Depends(get_current_user)):
    if current_user.user_id != user_id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="无权操作")
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    secret = generate_totp_secret()
    user.totp_secret_encrypted = encrypt_data(secret)
    user.auth_mode = "PASSWORD_AND_TOTP"
    db.commit()
    db.refresh(user)
    invalidate_user_status(user_id)
    uri = get_totp_uri(secret, user.username)
    return ApiResponse(code=0, message="ok", data={"secret": secret, "uri": uri}, request_id=str(uuid.uuid4()))


@router.post("/{user_id}/totp/disable")
def disable_totp(user_id: int, body: TOTPVerifyRequest, db: Session = Depends(get_db),
                 current_user: AuthContext = Depends(get_current_user)):
    if current_user.user_id != user_id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="无权操作")
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not user.totp_secret_encrypted:
        raise HTTPException(status_code=400, detail="TOTP 未启用")
    # 管理员操作跳过验证码；用户自己禁用需要验证码
    if current_user.role != "admin":
        if not body.code:
            raise HTTPException(status_code=400, detail="请输入 TOTP 验证码")
        secret = decrypt_data(user.totp_secret_encrypted)
        if not verify_totp(secret, body.code):
            raise HTTPException(status_code=400, detail="TOTP 验证码错误")
    user.totp_secret_encrypted = None
    user.auth_mode = "PASSWORD_ONLY"
    db.commit()
    invalidate_user_status(user_id)
    return ApiResponse(code=0, message="ok", data={"message": "TOTP 已禁用"}, request_id=str(uuid.uuid4()))


@router.post("/{user_id}/totp/reset")
def reset_totp(user_id: int, db: Session = Depends(get_db),
               current_user: AuthContext = Depends(require_role("admin"))):
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    secret = generate_totp_secret()
    user.totp_secret_encrypted = encrypt_data(secret)
    if user.auth_mode == "PASSWORD_ONLY":
        user.auth_mode = "PASSWORD_AND_TOTP"
    db.commit()
    db.refresh(user)
    invalidate_user_status(user_id)
    uri = get_totp_uri(secret, user.username)
    return ApiResponse(code=0, message="ok", data={"secret": secret, "uri": uri}, request_id=str(uuid.uuid4()))


@router.get("/{user_id}/totp/secret")
def get_totp_secret(user_id: int, db: Session = Depends(get_db),
                    current_user: AuthContext = Depends(require_role("admin"))):
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not user.totp_secret_encrypted:
        raise HTTPException(status_code=400, detail="TOTP 未启用")
    secret = decrypt_data(user.totp_secret_encrypted)
    uri = get_totp_uri(secret, user.username)
    return ApiResponse(code=0, message="ok", data={"secret": secret, "uri": uri}, request_id=str(uuid.uuid4()))
