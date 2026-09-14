"""查询缓存层 —— 进程内 TTL 缓存

已移除 Redis：单实例部署，进程内缓存即可满足查询加速需求。
"""

import fnmatch
import threading
import time
from typing import Any, Optional


class CacheService:
    """进程内 TTL 缓存（单例）

    惰性过期：get 命中时判断是否过期；写入超出容量时先清过期项，再淘汰最早到期项。
    FastAPI 请求线程与后台分析线程共用同一实例，读写加锁。
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            inst = super().__new__(cls)
            inst._init_store()
            cls._instance = inst
        return cls._instance

    def _init_store(self) -> None:
        self._data: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()
        self._max_entries = 512

    @property
    def available(self) -> bool:
        return True

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            if item[0] <= time.monotonic():
                self._data.pop(key, None)
                return None
            return item[1]

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        expire_at = time.monotonic() + (30 if ttl is None else ttl)
        with self._lock:
            if key not in self._data and len(self._data) >= self._max_entries:
                self._evict()
            self._data[key] = (expire_at, value)

    def _evict(self) -> None:
        now = time.monotonic()
        for k in [k for k, (exp, _) in self._data.items() if exp <= now]:
            self._data.pop(k, None)
        while len(self._data) >= self._max_entries:
            self._data.pop(min(self._data, key=lambda k: self._data[k][0]))

    def invalidate_pattern(self, pattern: str) -> None:
        with self._lock:
            for k in [k for k, _ in list(self._data.items()) if fnmatch.fnmatch(k, pattern)]:
                self._data.pop(k, None)

    def invalidate_metrics(self) -> None:
        """分析结果落库后只失效监测中心指标缓存

        告警列表/日志列表不能在这里清（分析持续写入，清了等于禁用缓存），
        由各自 TTL 保证新鲜度。
        """
        self.invalidate_pattern("metrics:*")


def get_cache() -> CacheService:
    return CacheService()
