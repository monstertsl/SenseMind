"""查询缓存层（已移除 Redis，无操作存根）

保留接口兼容性，所有缓存操作均为空操作。
"""

from typing import Any, Optional


class CacheService:
    """无操作缓存服务（单例）"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @property
    def available(self) -> bool:
        return False

    def get(self, key: str) -> Optional[Any]:
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        pass

    def invalidate_pattern(self, pattern: str) -> None:
        pass

    def invalidate_metrics(self) -> None:
        pass


def get_cache() -> CacheService:
    return CacheService()
