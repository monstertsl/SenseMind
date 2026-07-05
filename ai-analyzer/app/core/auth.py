"""认证核心：bcrypt + TOTP + JWT + 依赖注入"""

import os
import uuid
import logging
import hashlib
import base64
import bcrypt
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import pyotp
from sqlalchemy.orm import Session
from sqlalchemy import select

from .database import get_db
from .rate_limit import (
    get_cached_user_status,
    set_cached_user_status,
    invalidate_user_status,
    is_token_blacklisted,
    blacklist_token,
)
from .security import encrypt_data, decrypt_data
from ..db_models.user import User

logger = logging.getLogger(__name__)

security_scheme = HTTPBearer(auto_error=False)

ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_THRESHOLD_SECONDS = 10 * 60
GENERIC_AUTH_FAILURE = "用户名或口令错误"


def _get_secret_key() -> str:
    key = os.environ.get("SECRET_KEY", "")
    if not key or len(key) < 32:
        raise RuntimeError("SECRET_KEY 环境变量未配置或长度不足 32 字符")
    return key


def _pre_hash(password: str) -> bytes:
    """SHA256 预哈希绕过 bcrypt 72 字节限制（ES elastic 密码通常很长）。"""
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_pre_hash(password), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_pre_hash(plain), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "jti": str(uuid.uuid4())})
    return jwt.encode(to_encode, _get_secret_key(), algorithm="HS256")


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, _get_secret_key(), algorithms=["HS256"])
        return payload
    except JWTError:
        return None


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="SenseMind")


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


class AuthContext:
    def __init__(self, payload: dict, role: str, is_active: bool, auth_mode: str, user_id: int, username: str):
        self.user_id = user_id
        self.username = username
        self.role = role
        self.exp = payload.get("exp")
        self.jti = payload.get("jti", "")
        self.is_active = is_active
        self.auth_mode = auth_mode


def _load_user_status(user_id: int, db: Session) -> Optional[dict]:
    cached = get_cached_user_status(user_id)
    if cached:
        return cached
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        return None
    payload = {
        "role": user.role,
        "is_active": bool(user.is_active),
        "auth_mode": user.auth_mode,
    }
    set_cached_user_status(user_id, payload)
    return payload


def _maybe_refresh_token(ctx: AuthContext, response: Optional[Response]) -> None:
    if response is None or not ctx.exp:
        return
    now_ts = int(datetime.now(timezone.utc).timestamp())
    remaining = ctx.exp - now_ts
    if remaining <= 0 or remaining >= REFRESH_THRESHOLD_SECONDS:
        return
    new_token = create_access_token({
        "sub": str(ctx.user_id),
        "username": ctx.username,
        "role": ctx.role,
    })
    response.headers["X-Refreshed-Token"] = new_token
    response.headers["Access-Control-Expose-Headers"] = "X-Refreshed-Token"


def get_current_user(
    response: Response,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> AuthContext:
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未提供认证凭据")
    token = credentials.credentials
    payload = decode_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效或过期的令牌")

    jti = payload.get("jti", "")
    if jti and is_token_blacklisted(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="令牌已注销")

    try:
        user_id = int(payload.get("sub"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效的令牌载荷")

    status_info = _load_user_status(user_id, db)
    if not status_info:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户不存在")
    if not status_info.get("is_active", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="账号已被禁用")

    ctx = AuthContext(
        payload=payload,
        role=status_info.get("role") or payload.get("role", "user"),
        is_active=status_info.get("is_active", False),
        auth_mode=status_info.get("auth_mode", ""),
        user_id=user_id,
        username=payload.get("username", ""),
    )
    _maybe_refresh_token(ctx, response)
    return ctx


def require_role(required_role: str):
    def role_checker(current_user: AuthContext = Depends(get_current_user)):
        if required_role == "admin" and current_user.role != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="需要管理员权限")
        return current_user
    return role_checker
