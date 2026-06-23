"""告警去重缓存

基于 community_id + signature_id + 时间窗口的去重。
同一会话同一规则在时间窗口内只分析一次。

使用进程内存缓存，重启后清空（可接受，去重只是为了减少短时间内的重复调用）。
"""

import logging
import time
from collections import OrderedDict

logger = logging.getLogger(__name__)


class AlertDeduplicator:
    """告警去重器

    去重维度: community_id + signature_id
    有效期: dedup_window 秒（默认 600 秒 = 10 分钟）

    缓存结构:
        key = f"{community_id}:{signature_id}"
        value = {"analyzed_at": timestamp, "es_doc_id": "...", "verdict": "..."}

    LRU 淘汰: 超过 max_entries 时淘汰最早的记录
    """

    def __init__(self, dedup_window: int = 600, max_entries: int = 10000):
        self.dedup_window = dedup_window
        self.max_entries = max_entries
        self._cache: OrderedDict[str, dict] = OrderedDict()

        # 后台清理计数器（每 100 次检查清理一次过期项）
        self._access_count = 0

        logger.info(
            "告警去重器初始化: 窗口=%ds, 最大缓存=%d",
            dedup_window, max_entries,
        )

    def _make_key(self, community_id: str, signature_id: int) -> str:
        """生成去重 key"""
        return f"{community_id}:{signature_id}"

    def _cleanup(self):
        """清理过期缓存项"""
        now = time.time()
        expired_keys = [
            k for k, v in self._cache.items()
            if now - v["analyzed_at"] > self.dedup_window
        ]
        for k in expired_keys:
            del self._cache[k]
        if expired_keys:
            logger.debug("清理过期去重缓存: %d 条", len(expired_keys))

    def check(self, community_id: str, signature_id: int) -> dict | None:
        """检查告警是否在去重窗口内已分析过

        Args:
            community_id: 网络会话 ID
            signature_id: Suricata 规则 SID

        Returns:
            None=未重复（可分析），dict=已分析过（跳过，返回上次结果）
        """
        if not community_id or not signature_id:
            return None

        self._access_count += 1
        if self._access_count % 100 == 0:
            self._cleanup()

        key = self._make_key(community_id, signature_id)
        entry = self._cache.get(key)

        if entry is None:
            return None

        # 检查是否在窗口内
        now = time.time()
        if now - entry["analyzed_at"] > self.dedup_window:
            # 已过期，删除并允许分析
            del self._cache[key]
            return None

        # 命中去重，更新 LRU 顺序
        self._cache.move_to_end(key)
        logger.info(
            "告警命中去重: community_id=%s, signature_id=%d, 上次分析 %.0f 秒前, 判定=%s",
            community_id[:20], signature_id,
            now - entry["analyzed_at"],
            entry.get("verdict", "N/A"),
        )
        return entry

    def record(self, community_id: str, signature_id: int,
               es_doc_id: str = "", verdict: str = ""):
        """记录已分析的告警

        Args:
            community_id: 网络会话 ID
            signature_id: Suricata 规则 SID
            es_doc_id: ES 分析结果文档 ID
            verdict: 威胁判定结果
        """
        if not community_id or not signature_id:
            return

        key = self._make_key(community_id, signature_id)
        self._cache[key] = {
            "analyzed_at": time.time(),
            "es_doc_id": es_doc_id,
            "verdict": verdict,
        }

        # LRU 淘汰
        if len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)

    def stats(self) -> dict:
        """返回缓存统计"""
        return {
            "total_entries": len(self._cache),
            "dedup_window": self.dedup_window,
            "max_entries": self.max_entries,
        }
