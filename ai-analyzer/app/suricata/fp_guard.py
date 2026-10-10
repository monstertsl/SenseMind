"""Suricata 规则写入前的误报复核（False Positive Guard）

背景：AI 自动生成的规则存在一类「形态合规但语义空心」的高误报规则 ——
content 长度、数量都达标，但实际匹配的是「某业务接口 + 它的正常调用参数」，
上线后会持续产生海量噪声告警（历史案例：22 条 eWUISService/FileHandler 规则）。

本模块在规则写入前加两道防线，互为降级：

- **L2 证据层**：把规则 content 回放到 SIEM 历史 HTTP 流量（默认近 7 天），
  统计命中总数、独立源 IP 数、全部 content 同时命中的占比，并抽样真实 URI。
  作用是给二次评审提供「生成阶段没见过的新证据」，破解同源采样偏差
  （同一个模型看同一份上下文，第一遍判 low，第二遍多半还是 low）。
- **L1 裁定层**：由 LLM 站在防守评审视角做证伪式复核，并被要求主动构造
  3 个会命中该规则的正常业务请求样例 —— 举例越容易，规则越不特化。

降级策略（任一层不可用都不卡死规则生成链路）：
- ES 不可用 → 只跑 LLM 裁定
- LLM 不可用 / 超时 / 返回无法解析 → 只用回放证据做硬阈值裁定
- 两层都不可用 → 放行（回退到原有写入逻辑）
全程自动判定，不引入人工队列。
"""

import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# 过短 content（<4 字节）不做回放，噪声过大无统计意义
MIN_PROBE_LEN = 4


class RuleFpGuard:
    """规则写入前的误报复核器"""

    # ES 回放字段（HTTP URI / 请求体）
    URL_FIELD = "suricata.eve.http.url"
    BODY_FIELD = "suricata.eve.http.http_request_body"
    INDEX = "soc-*"

    # 判定为「业务常态签名」的默认硬阈值
    LOOKBACK_DAYS = 7
    REJECT_HITS = 100          # 主特征命中数下界
    REJECT_DISTINCT_SRC = 5    # 独立源 IP 数下界
    REJECT_COMBO_RATIO = 0.5   # 全部 content 组合命中占比（业务常态≈1.0）
    REJECT_HITS_ABSOLUTE = 50000  # 主特征绝对高频，此时用更低的占比门槛
    REJECT_ABSOLUTE_RATIO = 0.05  # 绝对高频下的组合占比门槛（真攻击≈0）

    # LLM 裁定的硬超时（秒）：超时立即降级为证据硬阈值，不卡住规则写入链路
    LLM_TIMEOUT = 30

    def __init__(self, llm=None, lookback_days: int = None,
                 reject_hits: int = None, reject_distinct_src: int = None,
                 reject_combo_ratio: float = None, reject_hits_absolute: int = None,
                 reject_absolute_ratio: float = None, llm_timeout: int = None):
        """
        Args:
            llm: LangChain Chat 模型实例（用于 L1 裁定），可为 None（仅用证据层）
            lookback_days: 回放时间窗口（天）
            reject_hits / reject_distinct_src / reject_combo_ratio: 组合占比型硬阈值
            reject_hits_absolute / reject_absolute_ratio: 主特征绝对高频时的硬阈值
            llm_timeout: LLM 裁定硬超时秒数，超时降级为证据硬阈值
        """
        self.llm = llm
        self.llm_timeout = llm_timeout if llm_timeout else self.LLM_TIMEOUT
        self.lookback_days = lookback_days or self.LOOKBACK_DAYS
        self.reject_hits = reject_hits if reject_hits is not None else self.REJECT_HITS
        self.reject_distinct_src = (
            reject_distinct_src if reject_distinct_src is not None else self.REJECT_DISTINCT_SRC
        )
        self.reject_combo_ratio = (
            reject_combo_ratio if reject_combo_ratio is not None else self.REJECT_COMBO_RATIO
        )
        self.reject_hits_absolute = (
            reject_hits_absolute if reject_hits_absolute is not None else self.REJECT_HITS_ABSOLUTE
        )
        self.reject_absolute_ratio = (
            reject_absolute_ratio if reject_absolute_ratio is not None else self.REJECT_ABSOLUTE_RATIO
        )
        self._es = None
        self._es_tried = False
        # 回放窗口是否已完成自适应（读取一次数据保留配置即可）
        self._lookback_resolved = False

    # ------------------------------------------------------------------
    # 回放窗口自适应
    # ------------------------------------------------------------------
    def _effective_lookback(self) -> int:
        """把回放窗口收敛到数据实际可用的天数

        soc-* 索引由每日清理任务按 `raw_log_retention_days` 删除过期索引，
        于是「数据真实跨度」通常比保留天数还少约 1 天（今天尚未过完）。
        若 lookback_days 超出数据范围，窗口后半段是空的，hits 会被系统性低估，
        中频伪规则就此绕过硬阈值 —— 且因为不报错，属于静默失效。
        因此这里取 min(lookback_days, raw_log_retention_days)。
        """
        if self._lookback_resolved:
            return self.lookback_days
        self._lookback_resolved = True
        try:
            from ..core.database import SessionLocal
            from ..db_models.system_config import SystemConfig

            with SessionLocal() as db:
                cfg = db.get(SystemConfig, 1)
                retention = getattr(cfg, "raw_log_retention_days", None)
            if isinstance(retention, int) and 0 < retention < self.lookback_days:
                logger.info(
                    "FP Guard 回放窗口自适应: %s 天 → %s 天（soc-* 索引保留天数上限）",
                    self.lookback_days, retention,
                )
                self.lookback_days = retention
        except Exception as e:
            logger.debug("FP Guard 读取数据保留配置失败，沿用 %s 天窗口: %s",
                         self.lookback_days, e)
        return self.lookback_days

    # ------------------------------------------------------------------
    # 对外主入口
    # ------------------------------------------------------------------
    def review(self, rule: str) -> tuple[bool, str]:
        """复核规则是否存在高误报风险

        Returns:
            (是否允许写入, 判定理由)。允许写入时理由用于日志审计。
        """
        if not rule or "content:" not in rule:
            return True, "无 content 特征，跳过复核"

        primary, others = self._pick_probe(rule)
        if not primary:
            return True, "无可回放特征（content 过短或无法落地到 ECS 字段）"

        stats = self._replay(primary, others)

        # 证据层优先：组合占比高 = 该规则命中的是一类普遍存在的流量形态
        if stats and self._evidence_says_reject(stats):
            return False, (
                f"回放证据判定为业务常态签名: {stats['hits']} 次命中/"
                f"{stats['distinct_src']} 个源 IP/组合占比 {self._fmt_ratio(stats['ratio'])}"
                f"（近 {stats['days']} 天）"
            )

        verdict = self._ask_llm(rule, primary, others, stats)
        if verdict is not None:
            allowed, reason = verdict
            if not allowed:
                return False, f"LLM 二次复核拒写: {reason}"
            return True, f"LLM 二次复核放行: {reason}"

        # LLM 不可用 → 退回纯证据判定
        return self._threshold_verdict(stats)

    # ------------------------------------------------------------------
    # 特征提取：把 content 落到对应的 ECS 字段
    # ------------------------------------------------------------------
    @staticmethod
    def _decode_hex(content: str) -> str:
        """解码 Suricata 管道符十六进制：|3c 3f 70 68 70| → <?php"""
        import re

        def sub(m):
            try:
                return bytes.fromhex(m.group(1).replace(" ", "")).decode("utf-8", errors="replace")
            except ValueError:
                return m.group(0)

        return re.sub(r"\|([0-9a-fA-F ]+)\|", sub, content)

    @classmethod
    def _contents_with_buffer(cls, rule: str) -> list:
        """按 Suricata sticky buffer 语义，把每个 content 归属到它的 buffer

        Returns:
            [(buffer, content, decoded), ...]，buffer 为 None 表示未指定
            （alert http 规则中未指定 buffer 的 content 匹配请求体）
        """
        results = []
        current = None
        for m in re.finditer(r'(http\.[a-z_]+)\s*;|content\s*:\s*"([^"]*)"', rule):
            buf = m.group(1)
            val = m.group(2)
            if buf:
                current = buf
                continue
            if val is None:
                continue
            results.append((current, val, cls._decode_hex(val)))
        return results

    @staticmethod
    def _field_for(buffer: str) -> str:
        """sticky buffer → ECS 字段（回放时用 .keyword 子字段做精确子串匹配）"""
        if buffer == "http.request_body":
            return RuleFpGuard.BODY_FIELD
        # http.uri / http.uri.raw / http.request_line / http.* 以及未指定 buffer
        return RuleFpGuard.URL_FIELD

    def _pick_probe(self, rule: str) -> tuple:
        """挑选回放主特征：解码后最长的 content，其余作为组合特征"""
        items = self._contents_with_buffer(rule)
        candidates = [
            (self._field_for(buf), val, dec)
            for buf, val, dec in items
            if len(dec) >= MIN_PROBE_LEN
        ]
        if not candidates:
            return None, []

        primary = max(candidates, key=lambda x: len(x[2]))
        others = [c for c in candidates if c is not primary][:5]
        return primary, others

    # ------------------------------------------------------------------
    # L2：ES 历史流量回放
    # ------------------------------------------------------------------
    def _get_es(self):
        """惰性获取 ES 只读客户端（失败只尝试一次）"""
        if self._es or self._es_tried:
            return self._es
        self._es_tried = True
        try:
            from ..services.es_reader import get_es_reader

            self._es = get_es_reader().client
        except Exception as e:
            logger.warning("FP Guard 无法初始化 ES 客户端，降级为纯 LLM 裁定: %s", e)
            self._es = None
        return self._es

    @staticmethod
    def _wildcard(field: str, value: str) -> dict:
        return {"wildcard": {f"{field}.keyword": {"value": f"*{value}*", "case_insensitive": True}}}

    def _replay(self, primary: tuple, others: list) -> dict | None:
        """在历史 HTTP 流量中回放规则特征

        Returns:
            {"hits","distinct_src","combined","ratio","body_probe","samples","days",
             "span_days","primary"}
            ratio 为 None 表示组合占比无法评估（单 content 或组合回放失败）
            span_days 为窗口内实际有数据的天数（< days 说明窗口未吃满，数据留存不足）
            回放失败返回 None
        """
        client = self._get_es()
        if client is None:
            return None

        days = self._effective_lookback()
        now = datetime.now(timezone.utc)
        since = (now - timedelta(days=days)).isoformat()
        base = [
            {"range": {"@timestamp": {"gte": since, "lte": now.isoformat()}}},
            {"exists": {"field": self.URL_FIELD}},
        ]

        field, raw, decoded = primary
        try:
            t0 = time.time()
            q_primary = {"bool": {"filter": base + [self._wildcard(field, decoded)]}}
            resp = client.search(
                index=self.INDEX,
                query=q_primary,
                size=5,
                track_total_hits=True,
                timeout="20s",
                aggs={
                    "src": {"cardinality": {"field": "source.ip", "precision_threshold": 200}},
                    # 匹配文档中最早的时间戳 → 推算窗口内实际有数据的天数
                    # （不用 date_histogram：该 agg 在本集群不接受 size 参数，
                    #   桶数受限会低估天数）
                    "oldest": {"min": {"field": "@timestamp"}},
                },
            )
            hits = resp["hits"]["total"]["value"]
            distinct_src = resp.get("aggregations", {}).get("src", {}).get("value", 0)
            oldest_ts = resp.get("aggregations", {}).get("oldest", {}).get("value_as_string")
            span_days = 0
            if oldest_ts:
                oldest = datetime.fromisoformat(oldest_ts.replace("Z", "+00:00"))
                span_days = int((now - oldest).total_seconds() // 86400) + 1
            samples = []
            for h in resp["hits"]["hits"]:
                http = (h.get("_source", {}).get("suricata", {}).get("eve", {}).get("http", {}) or {})
                url = http.get("url", "")
                if url and url not in samples:
                    samples.append(url[:300])
            logger.info("FP Guard 回放: 主特征=%s hits=%d src=%s 有效天数=%d/%d (%.1fs)",
                        decoded[:40], hits, distinct_src, span_days, days, time.time() - t0)
            if hits == 0:
                # 0 命中是静默失效的高危区：既可能是规则特征本就不在流量中（正常），
                # 也可能是数据留存不足/索引缺失导致窗口空转，必须留痕便于排查。
                logger.warning(
                    "FP Guard 回放 0 命中（主特征=%s，窗口 %s 天，其中实际有数据 %s 天）:"
                    "可能流量中不含该特征，也可能数据留存不足/索引缺失，请核对 soc-* 索引",
                    decoded[:40], days, span_days,
                )
        except Exception as e:
            logger.warning("FP Guard 回放失败（主特征=%s）: %s", decoded[:40], e)
            return None

        combined = None
        if others:
            try:
                filters = list(base) + [self._wildcard(field, decoded)]
                for f, _raw, dec in others:
                    filters.append(self._wildcard(f, dec))
                resp2 = client.search(
                    index=self.INDEX,
                    query={"bool": {"filter": filters}},
                    size=0,
                    track_total_hits=True,
                    timeout="20s",
                )
                combined = resp2["hits"]["total"]["value"]
            except Exception as e:
                # 组合回放失败时不得把占比当作命中，留空交给后续判定
                logger.warning("FP Guard 组合回放失败: %s", e)
                combined = None

        ratio = (combined / hits) if (hits and combined is not None) else None
        body_probe = any(f == self.BODY_FIELD for f, _r, _d in [primary] + others)
        return {
            "hits": hits,
            "distinct_src": distinct_src or 0,
            "combined": combined,
            "ratio": ratio,
            "span_days": span_days,
            "body_probe": body_probe,
            "samples": samples[:5],
            "days": self.lookback_days,
            "primary": decoded[:60],
        }

    # ------------------------------------------------------------------
    # 判定
    # ------------------------------------------------------------------
    @staticmethod
    def _fmt_ratio(ratio) -> str:
        return f"{ratio:.0%}" if ratio is not None else "未知"

    def _evidence_says_reject(self, stats: dict) -> bool:
        """证据层硬判定：命中的是一类普遍存在的流量形态

        两条判据：
        1. 中频多源 + 组合占比高 → 规则描述的是一类常规流量形态
        2. 主特征绝对高频：
           - 次要特征落在请求体（ES 请求体覆盖率远低于 URI，占比不可信）→ 判为业务常态
           - 占比无法评估（单 content / 组合回放失败）→ 同样判为业务常态
           - 纯 URI 特征且组合占比极低（真攻击≈0）→ 不拒，交给 LLM 复核
        """
        hits = stats["hits"]
        src = stats["distinct_src"]
        ratio = stats["ratio"]

        if (hits >= self.reject_hits and src >= self.reject_distinct_src
                and ratio is not None and ratio >= self.reject_combo_ratio):
            return True

        if hits >= self.reject_hits_absolute and src >= self.reject_distinct_src:
            if stats.get("body_probe") or ratio is None:
                return True
            return ratio >= self.reject_absolute_ratio

        return False

    def _threshold_verdict(self, stats: dict | None) -> tuple[bool, str]:
        """LLM 不可用时的兜底判定"""
        if stats is None:
            return True, "回放与 LLM 均不可用，放行（回退原逻辑）"
        if self._evidence_says_reject(stats):
            return False, (
                f"回放证据判定为业务常态签名（LLM 不可用）: {stats['hits']} 次/"
                f"{stats['distinct_src']} 源 IP/占比 {self._fmt_ratio(stats['ratio'])}"
            )
        return True, (
            f"回放证据未命中业务常态特征: {stats['hits']} 次/{stats['distinct_src']} 源 IP"
            f"/占比 {self._fmt_ratio(stats['ratio'])}（LLM 不可用，按证据放行）"
        )

    def _ask_llm(self, rule: str, primary: tuple, others: list, stats: dict | None) -> tuple | None:
        """L1 裁定：让 LLM 站在防守评审视角做证伪式复核

        Returns:
            (allowed, reason)，调用失败返回 None
        """
        if self.llm is None:
            return None
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            from ..json_utils import extract_json
        except Exception as e:
            logger.warning("FP Guard 无法加载 LLM 依赖: %s", e)
            return None

        evidence = "（回放不可用，请仅依据规则语义判断）"
        if stats:
            sample_text = "\n".join(f"  - {s}" for s in stats["samples"]) or "  （无）"
            span_note = ""
            if stats.get("span_days") is not None and stats["span_days"] < stats["days"]:
                span_note = (
                    f"（注意： {stats['days']} 天窗口内实际只有 {stats['span_days']} 天有数据，"
                    f"日志留存有限，命中数被相应低估）\n"
                )
            evidence = (
                f"把规则的每个 content 回放到生产环境近 {stats['days']} 天的真实 HTTP 流量后得到：\n"
                f"{span_note}"
                f"- 主特征 `{stats['primary']}` 命中总数：**{stats['hits']}** 次\n"
                f"- 发起这些请求的独立源 IP 数：**{stats['distinct_src']}**\n"
                f"- 同时命中规则全部 content 的比例：**{self._fmt_ratio(stats['ratio'])}**\n"
                f"- 真实 URI 样本（未截断前可能更长）：\n{sample_text}"
            )

        contents_text = "\n".join(
            f"  - [{f.split('.')[-2] if f.count('.') >= 2 else f}] {d}"
            for f, _r, d in [primary] + others
        )

        system = (
            "你是一名 IDS 规则质量评审专家，站在防守方/运维方立场，**任务是证伪**。\n"
            "另一位分析师从一条告警中提取并生成了下面的 Suricata 规则，他自评误报风险 low。"
            "你的职责是找出这条规则会命中正常业务流量的证据，而不是附和他。\n\n"
            "判定方法（按优先级）：\n"
            "1. 回放证据优先：若规则命中的是一类在日常流量中大量出现、来自众多不同源 IP 的流量形态，"
            "且这些样本看起来是正常业务调用，则必然高误报。\n"
            "2. 构造反例：尝试举出 3 个「完全正常、与攻击无关」的业务请求，"
            "若它们也会同时满足规则的每个 content，则规则不具攻击特异性，判定高误报。"
            "典型形态：规则的 content 组合只是「某个具体业务接口 + 它的正常参数」。\n"
            "3. 载荷缺失：msg 声称的攻击类型，在 content 中找不到对应强攻击载荷时"
            "（如声称路径穿越却没有 ../、..\\、%2e、/etc/passwd、win.ini 等），倾向高误报。\n"
            "4. 只有当规则确实含明确攻击载荷、且你想不出合理的正常业务解释时，才放行。\n\n"
            "只输出一个 JSON 对象，不要输出其他内容：\n"
            '{"decision":"allow|reject","fp_level":"low|medium|high",'
            '"reason":"不超过 60 字的中文判定理由","normal_traffic_examples":["样例 1","样例 2"]}'
        )
        user = (
            f"待评审规则：\n{rule}\n\n"
            f"规则 content 列表：\n{contents_text}\n\n"
            f"历史流量回放证据：\n{evidence}"
        )

        try:
            llm = self.llm
            try:
                # 裁定任务很短，压低 token 上限避免思考型模型啰嗦
                llm = llm.bind(max_tokens=1200)
            except Exception:
                pass
            # 硬超时：模型自身 timeout 通常配得很大（生成器要长回复），
            # 裁定任务是短任务，卡住即放弃并降级为证据硬阈值，避免阻塞规则写入
            pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="fp-guard-judge")
            try:
                future = pool.submit(
                    llm.invoke, [SystemMessage(content=system), HumanMessage(content=user)]
                )
                resp = future.result(timeout=self.llm_timeout)
            except FuturesTimeout:
                logger.warning(
                    "FP Guard LLM 裁定超时（>%ds），降级为证据硬阈值判定", self.llm_timeout
                )
                return None
            finally:
                # 不等待遗留线程，超时后由它在后台自行结束
                pool.shutdown(wait=False)
            text = getattr(resp, "content", "") or ""
            data = extract_json(text)
            if not data:
                logger.warning("FP Guard LLM 返回无法解析: %s", text[:200])
                return None
            decision = str(data.get("decision", "")).strip().lower()
            fp_level = str(data.get("fp_level", "")).strip().lower()
            reason = str(data.get("reason", ""))[:200]
            examples = data.get("normal_traffic_examples") or []
            if isinstance(examples, list) and examples:
                reason = f"{reason}｜反例: {str(examples[0])[:80]}"
            allowed = decision != "reject" and fp_level != "high"
            logger.info("FP Guard LLM 裁定: decision=%s fp_level=%s reason=%s",
                        decision, fp_level, reason)
            return allowed, reason
        except Exception as e:
            logger.warning("FP Guard LLM 裁定失败: %s", e)
            return None
