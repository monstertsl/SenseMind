"""登录限流 & Token 黑名单 & 用户状态缓存（进程内存实现）"""

import time
import threading
from collections import defaultdict


# ── 配置 ──────────────────────────────────────────────────
_AUTH_WINDOW_SECONDS: int = 60          # 限流窗口
_AUTH_IP_MAX_PER_WINDOW: int = 10       # 每 IP 每窗口最大尝试次数
_AUTH_USER_MAX_PER_WINDOW: int = 5      # 每用户每窗口最大尝试次数

CLEANUP_INTERVAL_SECONDS: int = 300  # 每 5 分钟清理过期黑名单


# ── 限流存储（进程内存） ─────────────────────────────────
# 格式：{"ip": {"count": N, "window_start": ts}, ...}
_ip_window: dict = defaultdict(lambda: {"count": 0, "window_start": 0.0})
_user_window: dict = defaultdict(lambda: {"count": 0, "window_start": 0.0})
_lock = threading.Lock()


# ── Token 黑名单（进程内存） ───────────────────────────────
# 格式：{jti: expiry_ts}
_token_blacklist: dict[str, float] = {}
_blacklist_lock = threading.Lock()


def _current_window_start() -> float:
    """当前窗口起点（按整分钟对齐）"""
    return int(time.time() / _AUTH_WINDOW_SECONDS) * _AUTH_WINDOW_SECONDS


# ══════════════════════════════════════════════════════════
# 登录限流
# ══════════════════════════════════════════════════════════

def check_auth_ip_limit(ip: str) -> tuple[bool, int]:
    """检查 IP 是否在限流窗口内。返回 (允许, 剩余次数)。"""
    now = time.time()
    win_start = _current_window_start()
    with _lock:
        entry = _ip_window[ip]
        if now - entry["window_start"] >= _AUTH_WINDOW_SECONDS:
            entry["count"] = 0
            entry["window_start"] = win_start
        remaining = _AUTH_IP_MAX_PER_WINDOW - entry["count"]
        return remaining > 0, max(0, remaining)


def check_auth_user_limit(username: str) -> tuple[bool, int]:
    """检查用户名是否在限流窗口内。返回 (允许, 剩余次数)。"""
    now = time.time()
    win_start = _current_window_start()
    with _lock:
        entry = _user_window[username]
        if now - entry["window_start"] >= _AUTH_WINDOW_SECONDS:
            entry["count"] = 0
            entry["window_start"] = win_start
        remaining = _AUTH_USER_MAX_PER_WINDOW - entry["count"]
        return remaining > 0, max(0, remaining)


def record_auth_failure(ip: str, username: str) -> None:
    """记录一次认证失败（同时递增 IP 和用户计数）。"""
    win_start = _current_window_start()
    with _lock:
        for key, storage in ((ip, _ip_window), (username, _user_window)):
            entry = storage[key]
            if time.time() - entry["window_start"] >= _AUTH_WINDOW_SECONDS:
                entry["count"] = 1
                entry["window_start"] = win_start
            else:
                entry["count"] += 1


def reset_auth_counters(ip: str, username: str) -> None:
    """登录成功后重置该 IP 和用户的失败计数。"""
    with _lock:
        _ip_window.pop(ip, None)
        _user_window.pop(username, None)


# ══════════════════════════════════════════════════════════
# Token 黑名单（进程内存）
# ══════════════════════════════════════════════════════════

def _cleanup_expired_blacklist() -> None:
    """清理过期的黑名单条目。"""
    now = time.time()
    with _blacklist_lock:
        expired = [jti for jti, exp in _token_blacklist.items() if exp < now]
        for jti in expired:
            del _token_blacklist[jti]


def blacklist_token(jti: str, ttl_seconds: int) -> None:
    """将 Token 加入黑名单，TTL 秒后过期。"""
    if ttl_seconds <= 0:
        return
    with _blacklist_lock:
        _token_blacklist[jti] = time.time() + ttl_seconds


def is_token_blacklisted(jti: str) -> bool:
    """检查 Token 是否在黑名单中。"""
    with _blacklist_lock:
        return jti in _token_blacklist and _token_blacklist[jti] > time.time()


# ══════════════════════════════════════════════════════════
# 用户状态缓存（已废弃，无需 Redis 缓存）
# ══════════════════════════════════════════════════════════

def get_cached_user_status(user_id: int) -> dict | None:
    """从缓存获取用户状态（当前不使用缓存，始终返回 None）。"""
    return None


def set_cached_user_status(user_id: int, data: dict) -> None:
    """设置用户状态缓存（当前不使用缓存，静默忽略）。"""
    pass


def invalidate_user_status(user_id: int) -> None:
    """使缓存中的用户状态失效（当前不使用缓存，静默忽略）。"""
    pass


# ── 定期清理（后台线程） ──────────────────────────────────

def _periodic_cleanup() -> None:
    """定期清理过期黑名单和限流记录。"""
    import time as _time_module
    while True:
        _time_module.sleep(CLEANUP_INTERVAL_SECONDS)
        _cleanup_expired_blacklist()
        # 清理超过 2 倍窗口时间的旧限流记录
        cutoff = _time_module.time() - _AUTH_WINDOW_SECONDS * 2
        with _lock:
            for storage in (_ip_window, _user_window):
                stale = [k for k, v in storage.items() if v["window_start"] < cutoff]
                for k in stale:
                    del storage[k]


_cleanup_thread = threading.Thread(target=_periodic_cleanup, daemon=True)
_cleanup_thread.start()
