"""Redis 缓存封装 —— 查询 API 加速层

TTL 分级：
- 指标聚合 30s（时效性优先）
- Mapping 10min（变化少）
- 列表 15s
- 详情 60s
"""

import json
import logging
import os
from typing import Any, Optional
import redis
from ..config import Config

logger = logging.getLogger(__name__)


class CacheService:
    """Redis 缓存服务，单例"""

    _instance = None
    _client = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_client()
        return cls._instance

    def _init_client(self):
        cfg = Config().redis
        password = ""
        pwd_env = cfg.get("password_env", "")
        if pwd_env:
            password = os.environ.get(pwd_env, "")
        try:
            self._client = redis.Redis(
                host=cfg.get("host", "redis"),
                port=cfg.get("port", 6379),
                db=cfg.get("db", 0),
                password=password or None,
                decode_responses=True,
                socket_timeout=3,
                socket_connect_timeout=2,
                retry_on_timeout=False,
            )
            self._client.ping()
            logger.info("Redis 连接成功: %s:%s", cfg.get("host"), cfg.get("port"))
        except Exception as e:
            logger.warning("Redis 连接失败，缓存层降级（直查 ES）: %s", e)
            self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None

    def get(self, key: str) -> Optional[Any]:
        """读缓存，返回反序列化后的对象"""
        if not self._client:
            return None
        try:
            raw = self._client.get(key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as e:
            logger.debug("缓存读取失败 key=%s: %s", key, e)
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """写缓存"""
        if not self._client:
            return
        try:
            cfg = Config().redis
            t = ttl if ttl is not None else cfg.get("default_ttl", 30)
            self._client.setex(key, t, json.dumps(value, ensure_ascii=False, default=str))
        except Exception as e:
            logger.debug("缓存写入失败 key=%s: %s", key, e)

    def invalidate_pattern(self, pattern: str) -> None:
        """按模式批量失效"""
        if not self._client:
            return
        try:
            # 使用 scan 避免阻塞
            cursor = 0
            while True:
                cursor, keys = self._client.scan(cursor=cursor, match=pattern, count=200)
                if keys:
                    self._client.delete(*keys)
                if cursor == 0:
                    break
        except Exception as e:
            logger.debug("缓存失效失败 pattern=%s: %s", pattern, e)

    def invalidate_metrics(self) -> None:
        """写入新 AI 研判时调用，失效指标缓存"""
        self.invalidate_pattern("metrics:*")
        self.invalidate_pattern("alerts:list:*")


# 单例便捷访问
def get_cache() -> CacheService:
    return CacheService()
