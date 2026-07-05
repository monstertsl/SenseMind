"""Redis 限流 + 用户状态缓存（同步，复用 SenseMind Redis 连接）"""

import os
import json
import logging
from typing import Optional, Tuple
import redis
from ..config import Config

logger = logging.getLogger(__name__)

# 限流参数
AUTH_IP_LIMIT = 30
AUTH_IP_WINDOW = 60
AUTH_USER_1M_LIMIT = 10
AUTH_USER_1M_WINDOW = 60

# 用户状态缓存
USER_STATUS_TTL = 45

_client: Optional[redis.Redis] = None


def _get_redis() -> Optional[redis.Redis]:
    global _client
    if _client is not None:
        return _client
    cfg = Config().redis
    password = ""
    pwd_env = cfg.get("password_env", "")
    if pwd_env:
        password = os.environ.get(pwd_env, "")
    try:
        _client = redis.Redis(
            host=cfg.get("host", "redis"),
            port=cfg.get("port", 6379),
            db=cfg.get("db", 0),
            password=password or None,
            decode_responses=True,
            socket_timeout=3,
            socket_connect_timeout=2,
        )
        _client.ping()
        return _client
    except Exception as e:
        logger.warning("限流模块 Redis 连接失败: %s", e)
        _client = None
        return None


def _incr_with_expire(key: str, window: int) -> int:
    r = _get_redis()
    if not r:
        return 0
    n = r.incr(key)
    if n == 1:
        r.expire(key, window)
    return int(n)


def check_auth_ip_limit(client_ip: str) -> Tuple[bool, int]:
    if not client_ip:
        return True, 0
    r = _get_redis()
    if not r:
        return True, 0
    key = f"rate:auth:ip:{client_ip}"
    val = r.get(key)
    current = int(val) if val else 0
    if current >= AUTH_IP_LIMIT:
        ttl = r.ttl(key)
        return False, ttl if ttl > 0 else AUTH_IP_WINDOW
    return True, 0


def check_auth_user_limit(username: str) -> Tuple[bool, int]:
    if not username:
        return True, 0
    r = _get_redis()
    if not r:
        return True, 0
    key = f"rate:auth:user:1m:{username}"
    val = r.get(key)
    current = int(val) if val else 0
    if current >= AUTH_USER_1M_LIMIT:
        ttl = r.ttl(key)
        return False, ttl if ttl > 0 else AUTH_USER_1M_WINDOW
    return True, 0


def record_auth_failure(client_ip: Optional[str], username: Optional[str]) -> None:
    if client_ip:
        _incr_with_expire(f"rate:auth:ip:{client_ip}", AUTH_IP_WINDOW)
    if username:
        _incr_with_expire(f"rate:auth:user:1m:{username}", AUTH_USER_1M_WINDOW)


def reset_auth_counters(client_ip: Optional[str], username: Optional[str]) -> None:
    r = _get_redis()
    if not r:
        return
    keys = []
    if client_ip:
        keys.append(f"rate:auth:ip:{client_ip}")
    if username:
        keys.append(f"rate:auth:user:1m:{username}")
    if keys:
        r.delete(*keys)


# ---- 用户状态缓存 ----

def get_cached_user_status(user_id: int) -> Optional[dict]:
    r = _get_redis()
    if not r:
        return None
    data = r.get(f"user:status:{user_id}")
    if data:
        try:
            return json.loads(data)
        except Exception:
            return None
    return None


def set_cached_user_status(user_id: int, payload: dict) -> None:
    r = _get_redis()
    if not r:
        return
    r.setex(f"user:status:{user_id}", USER_STATUS_TTL, json.dumps(payload, default=str))


def invalidate_user_status(user_id) -> None:
    r = _get_redis()
    if not r:
        return
    r.delete(f"user:status:{user_id}")


# ---- Token 黑名单 ----

def blacklist_token(jti: str, ttl: int) -> None:
    r = _get_redis()
    if not r:
        return
    r.setex(f"token:blacklist:{jti}", max(ttl, 60), "1")


def is_token_blacklisted(jti: str) -> bool:
    r = _get_redis()
    if not r:
        return False
    return bool(r.get(f"token:blacklist:{jti}"))
