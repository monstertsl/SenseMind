"""告警去重缓存

三维度去重：
1. community_id + signature_id：同一会话同一规则只分析一次
2. source_ip + signature_id：同一源IP同一规则在时间窗口内只分析一次
   （防止端口扫描等场景产生大量不同 community_id 但相同攻击类型的告警）
3. community_id（流级别）：同一网络会话（flow）在时间窗口内只分析一次，
   不论触发的是哪条规则。用于抑制同一攻击被多条变体规则（如 Remote/Local
   Instance）分别触发而产生的重复分析。

使用进程内存缓存，重启后清空（可接受，去重只是为了减少短时间内的重复调用）。
"""

import logging
import time
from collections import OrderedDict

logger = logging.getLogger(__name__)


class AlertDeduplicator:
    """告警去重器

    去重维度:
      - 精确去重: community_id + signature_id
      - 宽泛去重: source_ip + signature_id（防止扫描类攻击爆炸）

    有效期: dedup_window 秒（默认 600 秒 = 10 分钟）

    缓存结构:
        key = f"{community_id}:{signature_id}" 或 f"ip:{source_ip}:{signature_id}"
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
        """生成精确去重 key"""
        return f"{community_id}:{signature_id}"

    def _make_ip_key(self, source_ip: str, signature_id: int) -> str:
        """生成源IP去重 key"""
        return f"ip:{source_ip}:{signature_id}"

    def _make_flow_key(self, community_id: str) -> str:
        """生成流级别去重 key（同一会话不论哪条规则只分析一次）"""
        return f"flow:{community_id}"

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

    def check(self, community_id: str, signature_id: int,
              source_ip: str = "") -> dict | None:
        """检查告警是否在去重窗口内已分析过

        Args:
            community_id: 网络会话 ID
            signature_id: Suricata 规则 SID
            source_ip: 源 IP（用于宽泛去重）

        Returns:
            None=未重复（可分析），dict=已分析过（跳过，返回上次结果）
        """
        if not signature_id:
            return None

        self._access_count += 1
        if self._access_count % 100 == 0:
            self._cleanup()

        now = time.time()

        # 1. 精确去重: community_id + signature_id
        if community_id:
            key = self._make_key(community_id, signature_id)
            entry = self._cache.get(key)
            if entry is not None:
                if now - entry["analyzed_at"] <= self.dedup_window:
                    self._cache.move_to_end(key)
                    logger.info(
                        "告警命中精确去重: community_id=%s, signature_id=%d, 上次分析 %.0f 秒前, 判定=%s",
                        community_id[:20], signature_id,
                        now - entry["analyzed_at"],
                        entry.get("verdict", "N/A"),
                    )
                    return entry
                else:
                    del self._cache[key]

        # 2. 宽泛去重: source_ip + signature_id
        if source_ip:
            ip_key = self._make_ip_key(source_ip, signature_id)
            entry = self._cache.get(ip_key)
            if entry is not None:
                if now - entry["analyzed_at"] <= self.dedup_window:
                    self._cache.move_to_end(ip_key)
                    logger.info(
                        "告警命中源IP去重: source_ip=%s, signature_id=%d, 上次分析 %.0f 秒前, 判定=%s",
                        source_ip, signature_id,
                        now - entry["analyzed_at"],
                        entry.get("verdict", "N/A"),
                    )
                    return entry
                else:
                    del self._cache[ip_key]

        # 3. 流级别去重: 同一 community_id（不论哪条规则）只分析一次
        #    抑制同一攻击被多条变体规则（如 Remote/Local Instance）分别触发
        if community_id:
            flow_key = self._make_flow_key(community_id)
            entry = self._cache.get(flow_key)
            if entry is not None:
                if now - entry["analyzed_at"] <= self.dedup_window:
                    self._cache.move_to_end(flow_key)
                    logger.info(
                        "告警命中流级别去重: community_id=%s, 上次分析 %.0f 秒前, 判定=%s",
                        community_id[:20],
                        now - entry["analyzed_at"],
                        entry.get("verdict", "N/A"),
                    )
                    return entry
                else:
                    del self._cache[flow_key]

        return None

    def record(self, community_id: str, signature_id: int,
               es_doc_id: str = "", verdict: str = "",
               source_ip: str = ""):
        """记录已分析的告警

        Args:
            community_id: 网络会话 ID
            signature_id: Suricata 规则 SID
            es_doc_id: ES 分析结果文档 ID
            verdict: 威胁判定结果
            source_ip: 源 IP（用于宽泛去重）
        """
        if not signature_id:
            return

        now = time.time()
        entry = {
            "analyzed_at": now,
            "es_doc_id": es_doc_id,
            "verdict": verdict,
        }

        # 精确去重 key
        if community_id:
            key = self._make_key(community_id, signature_id)
            self._cache[key] = entry

        # 流级别去重 key（同一会话不论哪条规则只分析一次）
        if community_id:
            flow_key = self._make_flow_key(community_id)
            self._cache[flow_key] = entry

        # 源IP去重 key（共享 entry 副本）
        if source_ip:
            ip_key = self._make_ip_key(source_ip, signature_id)
            self._cache[ip_key] = entry.copy()

        # LRU 淘汰
        while len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)

    def stats(self) -> dict:
        """返回缓存统计"""
        return {
            "total_entries": len(self._cache),
            "dedup_window": self.dedup_window,
            "max_entries": self.max_entries,
        }
