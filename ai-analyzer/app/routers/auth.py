"""认证路由：check-user / login / logout / me"""

import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.database import get_db
from ..core.auth import (
    hash_password, verify_password, create_access_token, decode_token,
    verify_totp, get_current_user, AuthContext,
)
from ..core.security import encrypt_data, decrypt_data
from ..core.audit import write_login_log
from ..core.rate_limit import (
    check_auth_ip_limit, check_auth_user_limit,
    record_auth_failure, reset_auth_counters,
    invalidate_user_status, blacklist_token,
)
from ..db_models.user import User
from ..db_models.system_config import SystemConfig
from ..schemas import ApiResponse

router = APIRouter(prefix="/api/v1/auth", tags=["认证"])

GENERIC_AUTH_FAILURE = "用户名或口令错误"


@router.get("/check-ip")
def check_ip(request: Request, db: Session = Depends(get_db)):
    """Nginx auth_request 子请求端点：检查客户端 IP 是否在白名单

    白名单为空时允许所有 IP；非空时只允许白名单内的 IP。
    供 Nginx auth_request 调用，不需要认证。
    """
    client_ip = _extract_client_ip(request)
    cfg = db.execute(select(SystemConfig).where(SystemConfig.id == 1)).scalar_one_or_none()

    if cfg and cfg.allowed_login_ips:
        allowed_ips = [ip.strip() for ip in cfg.allowed_login_ips.split(",") if ip.strip()]
        if allowed_ips and client_ip not in allowed_ips:
            raise HTTPException(status_code=403, detail="IP not allowed")

    return {"status": "ok"}


class CheckUserRequest(BaseModel):
    username: str


class LoginRequest(BaseModel):
    username: str
    password: str | None = None
    totp_code: str | None = None


def _extract_client_ip(request: Request) -> str:
    return (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or request.headers.get("x-real-ip", "")
        or (request.client.host if request.client else "unknown")
    )


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


@router.post("/check-user")
def check_user(body: CheckUserRequest, request: Request, db: Session = Depends(get_db)):
    """探测用户存在性与认证模式（不存在也返回 PASSWORD_ONLY 防枚举）"""
    client_ip = _extract_client_ip(request)
    allowed, _ = check_auth_ip_limit(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail="请求过于频繁，请稍后再试")

    user = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    if not user:
        return ApiResponse(code=0, message="ok", data={
            "exists": True, "auth_mode": "PASSWORD_ONLY", "totp_enabled": False,
        }, request_id=str(uuid.uuid4()))

    return ApiResponse(code=0, message="ok", data={
        "exists": True,
        "auth_mode": user.auth_mode,
        "totp_enabled": bool(user.totp_secret_encrypted),
    }, request_id=str(uuid.uuid4()))


def _record_failed_login(user: User, db: Session, *, username: str,
                          client_ip: str, reason: str, fail_limit: int) -> None:
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= fail_limit:
        user.is_active = False
    write_login_log(
        db, username=username, success=False, ip_address=client_ip,
        detail=f"登录失败：{reason} (attempt {user.failed_login_attempts})",
    )
    invalidate_user_status(user.id)
    record_auth_failure(client_ip, username)


@router.post("/login")
def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):
    client_ip = _extract_client_ip(request)

    # 限流
    allowed, _ = check_auth_ip_limit(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail="请求过于频繁，请稍后再试")
    allowed, _ = check_auth_user_limit(body.username)
    if not allowed:
        raise HTTPException(status_code=429, detail="请求过于频繁，请稍后再试")

    # 读取失败次数限制
    cfg = db.execute(select(SystemConfig).where(SystemConfig.id == 1)).scalar_one_or_none()
    fail_limit = cfg.login_fail_limit if cfg else 5

    user = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()

    if not user:
        write_login_log(
            db, username=body.username, success=False, ip_address=client_ip,
            detail="登录失败：用户不存在",
        )
        record_auth_failure(client_ip, body.username)
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    if not user.is_active:
        write_login_log(
            db, username=body.username, success=False, ip_address=client_ip,
            detail="登录失败：账号已禁用",
        )
        raise HTTPException(status_code=403, detail="账号已被禁用，请联系管理员")

    # IP 白名单校验
    if cfg and cfg.allowed_login_ips:
        allowed_ips = [ip.strip() for ip in cfg.allowed_login_ips.split(",") if ip.strip()]
        if allowed_ips and client_ip not in allowed_ips:
            write_login_log(
                db, username=body.username, success=False, ip_address=client_ip,
                detail="登录失败：IP 不允许",
            )
            raise HTTPException(status_code=403, detail="该 IP 不允许登录")

    # 按认证模式校验
    if user.auth_mode == "TOTP_ONLY":
        if not body.totp_code:
            raise HTTPException(status_code=400, detail="需要 TOTP 验证码", headers={"X-Need-Totp": "1"})
        if not user.totp_secret_encrypted:
            raise HTTPException(status_code=400, detail="TOTP 未配置，请联系管理员")
        secret = decrypt_data(user.totp_secret_encrypted)
        if not verify_totp(secret, body.totp_code):
            _record_failed_login(user, db, username=body.username, client_ip=client_ip,
                                 reason="Wrong TOTP code", fail_limit=fail_limit)
            raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    elif user.auth_mode == "PASSWORD_ONLY":
        if not body.password:
            raise HTTPException(status_code=400, detail="请输入密码")
        if not verify_password(body.password, user.password_hash):
            _record_failed_login(user, db, username=body.username, client_ip=client_ip,
                                 reason="Wrong password", fail_limit=fail_limit)
            raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    elif user.auth_mode == "PASSWORD_AND_TOTP":
        if not body.password:
            raise HTTPException(status_code=400, detail="请输入密码")
        if not verify_password(body.password, user.password_hash):
            _record_failed_login(user, db, username=body.username, client_ip=client_ip,
                                 reason="Wrong password", fail_limit=fail_limit)
            raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)
        if not body.totp_code:
            raise HTTPException(status_code=400, detail="需要 TOTP 验证码", headers={"X-Need-Totp": "1"})
        if not user.totp_secret_encrypted:
            raise HTTPException(status_code=400, detail="TOTP 未配置，请联系管理员")
        secret = decrypt_data(user.totp_secret_encrypted)
        if not verify_totp(secret, body.totp_code):
            _record_failed_login(user, db, username=body.username, client_ip=client_ip,
                                 reason="Wrong TOTP code", fail_limit=fail_limit)
            raise HTTPException(status_code=401, detail=GENERIC_AUTH_FAILURE)

    # 登录成功
    user.failed_login_attempts = 0
    user.last_login_at = datetime.utcnow()
    write_login_log(
        db, username=body.username, success=True, ip_address=client_ip,
        detail="登录成功",
    )
    invalidate_user_status(user.id)
    reset_auth_counters(client_ip, body.username)

    access_token = create_access_token({
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
    })

    return ApiResponse(code=0, message="ok", data={
        "access_token": access_token,
        "user": _user_to_dict(user),
    }, request_id=str(uuid.uuid4()))


@router.post("/logout")
def logout(current_user: AuthContext = Depends(get_current_user)):
    import time
    remaining_ttl = (current_user.exp or int(time.time()) + 60) - int(time.time())
    blacklist_token(current_user.jti, remaining_ttl)
    invalidate_user_status(current_user.user_id)
    return ApiResponse(code=0, message="ok", data={"message": "已注销"}, request_id=str(uuid.uuid4()))


@router.get("/me")
def get_me(current_user: AuthContext = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.execute(select(User).where(User.id == current_user.user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    return ApiResponse(code=0, message="ok", data=_user_to_dict(user), request_id=str(uuid.uuid4()))
