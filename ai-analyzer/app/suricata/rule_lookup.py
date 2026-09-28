"""按 sid 反查规则的 content 字面量

用途：告警详情在 Payload / Response Body 上高亮"命中的规则片段"。
约束：Suricata 的 eve.json 只记录命中的 sid，不记录命中偏移，
因此只能由 sid 回查规则原文、把 content 还原成字面量做子串匹配（近似还原）。
"""

import logging
import os
import re
import threading
import time

logger = logging.getLogger(__name__)

# 纯符号片段（{{、}}、${ 等）2 个字符就有明确语义；
# 含字母数字的片段短于 3 字符会在正常流量里到处命中，噪音大于价值
MIN_LITERAL_LEN = 3
MIN_SYMBOL_LITERAL_LEN = 2

# 规则文件会被 AI 规则池频繁追加，索引按 TTL + 文件指纹失效
CACHE_TTL_SECONDS = 60

_SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")
_CONTENT_RE = re.compile(r'^\s*content\s*:\s*(!?)\s*(?:"([^"]*)"|([^\s;]+))\s*$')
_PCRE_RE = re.compile(r'^\s*pcre\s*:\s*"([^"]*)"\s*$')
_HEX_RE = re.compile(r"\|([0-9a-fA-F ]+)\|")
_NOCASE_RE = re.compile(r"\bnocase\b")

# pcre 中的正则元字符（未转义时视为字面段分隔）
# content 后紧跟 distance:0 = 该片段紧邻上一片段（拼接后才是完整特征）
_DISTANCE0_RE = re.compile(r"^\s*distance\s*:\s*0\s*$")

_PCRE_META = set(".*+?()[]{}|^$")
# \d \w \s \b 等字符类：不是字面量，同样断句
_PCRE_CLASS_ESCAPE = set("dwsWSbABDnrt")


def _keep_literal(value: str) -> bool:
    """字面量是否值得高亮"""
    value = value.strip()
    if not value:
        return False
    if any(c.isalnum() for c in value):
        return len(value) >= MIN_LITERAL_LEN
    return len(value) >= MIN_SYMBOL_LITERAL_LEN


def _pcre_literals(pcre: str) -> tuple:
    r"""从 pcre 中抽取字面片段

    正则语义无法完整还原，只取连续的字面段用于高亮：
    /\{\{.*?\*.*?\}\}/ → ['{{', '}}']

    Returns:
        (片段列表, 是否含 /i 忽略大小写)
    """
    value = pcre.strip()
    # 否定 pcre 不表示命中
    if value.startswith("!"):
        return [], False
    match = re.match(r"^/(.*)/([A-Za-z]*)$", value, re.DOTALL)
    if not match:
        return [], False
    body, flags = match.group(1), match.group(2)

    out: list = []
    buf: list = []

    def flush():
        text = "".join(buf).strip()
        buf.clear()
        if _keep_literal(text):
            out.append(text)

    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            nxt = body[i + 1] if i + 1 < len(body) else ""
            if nxt in _PCRE_CLASS_ESCAPE:
                flush()
                i += 2
                continue
            hex_match = re.match(r"x([0-9a-fA-F]{2})", body[i + 1:i + 4])
            if nxt == "x" and hex_match:
                buf.append(chr(int(hex_match.group(1), 16)))
                i += 4
                continue
            # \. \( \/ 等：转义后的字面字符
            buf.append(nxt)
            i += 2
            continue
        if ch in _PCRE_META:
            flush()
            i += 1
            continue
        buf.append(ch)
        i += 1
    flush()
    return out, "i" in flags.lower()


def _decode_hex(value: str) -> str:
    """|3c 3f 70 68 70| → <?php

    不可打印字节用 latin-1 保留原字节，payload_printable 里它们已被替换成 '.'，
    这类片段自然匹配不上（不高亮），属预期行为。
    """

    def replace(match):
        raw = match.group(1).replace(" ", "")
        try:
            return bytes.fromhex(raw).decode("latin-1")
        except ValueError:
            return match.group(0)

    return _HEX_RE.sub(replace, value)


def _unescape(value: str) -> str:
    return value.replace('\\"', '"').replace("\\\\", "\\").replace("\\;", ";")


def _next_is_distance0(options: list, idx: int) -> bool:
    """content 自身是否带 distance:0（中间允许夹 nocase 等修饰词）

    distance 写在 content 之后但修饰"本片段与上一片段"的关系：
    content:"${"; content:"j"; distance:0  → j 紧接在 ${ 之后。
    """
    for j in range(idx + 1, min(idx + 4, len(options))):
        token = options[j]
        if _DISTANCE0_RE.match(token):
            return True
        # 碰到下一个 content / pcre 说明 distance 没有出现
        if _CONTENT_RE.match(token) or _PCRE_RE.match(token):
            return False
    return False


def _merge_adjacent(entries: list) -> list:
    """把 distance:0 串联的 content 拼成连续字面量

    部分规则（如 Log4Shell sid 91252）把 "${jndi:" 拆成
    content:"${"; content:"j"; distance:0; ... —— 单字符片段没有高亮价值，
    只有拼回去才看得出命中特征。原片段仍保留：变形载荷（${${lower:j}ndi:）
    拼串匹配不上时，至少还能高亮 "${"。
    """
    if len(entries) < 2:
        return []
    out: list = []
    buf = [entries[0][0]]

    def flush():
        text = "".join(buf)
        buf.clear()
        if len(text) > 1 and _keep_literal(text) and text not in out:
            out.append(text)

    for idx in range(1, len(entries)):
        value, adjacent_to_prev = entries[idx]
        if adjacent_to_prev:
            buf.append(value)
            continue
        flush()
        buf.append(value)
    flush()
    return out


def _rule_body(rule: str) -> str:
    """取规则选项区（括号内部分）"""
    if "(" in rule and ")" in rule:
        return rule.split("(", 1)[1].rsplit(")", 1)[0]
    return rule


def parse_rule_contents(rule: str) -> tuple:
    """提取规则中可用于高亮的字面量

    Returns:
        (contents, nocase)
        contents: 正向 content 还原后的字面量列表（否定 content 与 pcre 无法还原，跳过）
        nocase: 规则选项区是否含 nocase（含则前端按忽略大小写匹配）
    """
    body = _rule_body(rule)
    options = [t.strip() for t in body.split(";")]
    contents = []
    entries: list = []  # [(字面量, 后跟 distance:0)]
    pcre_list = []
    for idx, token in enumerate(options):
        match = _CONTENT_RE.match(token)
        if match:
            # content:!"..."（否定匹配）不能当作命中片段
            if match.group(1) == "!":
                continue
            raw = match.group(2) if match.group(2) is not None else match.group(3)
            value = _unescape(_decode_hex(raw))
            entries.append((value, _next_is_distance0(options, idx)))
            if _keep_literal(value):
                contents.append(value)
            continue
        pcre_match = _PCRE_RE.match(token)
        if pcre_match:
            pcre_list.append(pcre_match.group(1))

    # distance:0 串联的片段拼回完整特征（如 ${ + j + n + d + i + : → ${jndi:）
    for value in _merge_adjacent(entries):
        if value not in contents:
            contents.append(value)

    nocase = bool(_NOCASE_RE.search(body))
    if contents:
        return contents, nocase

    # 无可高亮 content（纯 pcre 规则）：退而从 pcre 抽字面片段
    literals: list = []
    for pcre in pcre_list:
        parts, ci = _pcre_literals(pcre)
        literals.extend(parts)
        nocase = nocase or ci
    return literals, nocase


class RuleLookup:
    """sid → content 字面量索引（按文件指纹 + TTL 失效）"""

    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self._index: dict = {}
        self._nocase: dict = {}
        self._stamp: tuple = ()
        self._built_at = 0.0
        self._lock = threading.Lock()

    def _rule_files(self) -> list:
        """现行规则 + 备份文件

        备份必须纳入：规则被删除或收编重编号后，历史告警仍带着旧 sid，
        只在现行规则里查会导致绝大多数历史告警取不到命中片段。
        """
        if not self.rules_dir or not os.path.isdir(self.rules_dir):
            return []
        names = [n for n in os.listdir(self.rules_dir)
                 if os.path.isfile(os.path.join(self.rules_dir, n))]
        main_files = sorted(n for n in names if n.endswith(".rules"))
        backup_files = sorted(n for n in names if ".bak" in n)
        return [os.path.join(self.rules_dir, n) for n in main_files + backup_files]

    def _stamp_now(self) -> tuple:
        stamp = []
        for path in self._rule_files():
            try:
                stat = os.stat(path)
                stamp.append((path, int(stat.st_mtime), stat.st_size))
            except OSError:
                continue
        return tuple(stamp)

    def _rebuild(self):
        with self._lock:
            self._build()

    def _build(self):
        index: dict = {}
        nocase: dict = {}
        for path in self._rule_files():
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        match = _SID_RE.search(line)
                        if not match:
                            continue
                        sid = int(match.group(1))
                        contents, ci = parse_rule_contents(line)
                        if not contents:
                            continue
                        # sid 会被回收复用（同一 sid 在现行规则与历史备份里可能指向不同规则），
                        # 无法判定告警属于哪一版 → 合并所有版本的片段，宁可多标不可漏标
                        if sid not in index:
                            index[sid] = []
                        for value in contents:
                            if value not in index[sid]:
                                index[sid].append(value)
                        nocase[sid] = nocase.get(sid, False) or ci
            except OSError as e:
                logger.warning("读取规则文件失败 %s: %s", path, e)
        self._index = index
        self._nocase = nocase
        self._stamp = self._stamp_now()
        self._built_at = time.time()
        logger.info("规则字面量索引已构建: %d 条 sid, 目录=%s", len(index), self.rules_dir)

    def warmup(self):
        """预热索引：规则目录含备份约 20MB，构建 1~2s，避免首个请求被拖慢"""
        if self._index:
            return
        try:
            self._rebuild()
        except Exception as e:
            logger.warning("规则字面量索引预热失败: %s", e)

    def get(self, sid) -> dict:
        try:
            sid = int(sid)
        except (TypeError, ValueError):
            sid = 0
        # 语义检测（sid=0）等无规则场景直接返回空，不做文件 IO
        if sid <= 0:
            return {"sid": 0, "contents": [], "nocase": False}

        expired = time.time() - self._built_at > CACHE_TTL_SECONDS
        if not self._index or expired:
            if not self._index or self._stamp != self._stamp_now():
                self._rebuild()
            else:
                self._built_at = time.time()

        return {
            "sid": sid,
            "contents": self._index.get(sid, []),
            "nocase": self._nocase.get(sid, False),
        }


_lookup = None


def get_rule_lookup() -> RuleLookup:
    """进程内单例，规则目录取 suricata.rules_file 所在目录"""
    global _lookup
    if _lookup is None:
        rules_dir = "/suricata/rules"
        try:
            from ..config import Config

            rules_file = Config().suricata.get("rules_file", "/suricata/rules/local.rules")
            rules_dir = os.path.dirname(rules_file) or rules_dir
        except Exception as e:
            logger.warning("读取规则目录配置失败，回退默认目录: %s", e)
        _lookup = RuleLookup(rules_dir)
    return _lookup
