"""Suricata 规则写入器

负责将 AI 生成的规则写入 local.rules 文件，
并通过 Docker Engine API 热加载规则。

规则文件: /data/suricata/lib/rules/local.rules (宿主机)
          → /var/lib/suricata/rules/local.rules (suricata 容器)
          → /suricata/rules/local.rules (ai-analyzer 容器)

热加载: 通过 Docker Engine API（/var/run/docker.sock）在 suricata 容器内
        执行 suricatasc -c reload-rules，无需安装 docker CLI。
"""

import logging
import os
import subprocess
import re
import json
import shlex
import httpx
import threading

logger = logging.getLogger(__name__)

# 全局写锁，防止并发写入导致 SID 重复
_write_lock = threading.Lock()


class RuleWriter:
    """Suricata 本地规则写入器"""

    # AI 本地规则 SID 范围
    SID_MIN = 9000001
    SID_MAX = 9999999

    def __init__(self, rules_file: str, suricata_container: str = "suricata"):
        """
        Args:
            rules_file: local.rules 文件路径（ai-analyzer 容器内）
            suricata_container: suricata 容器名称，用于 docker exec 热加载
        """
        self.rules_file = rules_file
        self.suricata_container = suricata_container

        # 确保规则文件存在
        os.makedirs(os.path.dirname(rules_file), exist_ok=True)
        if not os.path.exists(rules_file):
            open(rules_file, "w").close()
            logger.info("创建 local.rules: %s", rules_file)

        # 加载已有 SID 集合（去重用）
        self._existing_sids = set()
        self._existing_rules = set()
        # 预计算每条已有规则的核心特征（归一化后的最长 content），
        # 避免每次去重都重新提取
        self._existing_core_features = set()
        self._load_existing()

        logger.info(
            "RuleWriter 初始化: file=%s, container=%s, 已有 %d 条规则",
            rules_file,
            suricata_container,
            len(self._existing_sids),
        )

    def _load_existing(self):
        """加载已有的规则和 SID"""
        try:
            with open(self.rules_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    self._existing_rules.add(line)
                    # 提取 SID
                    if "sid:" in line:
                        sid_start = line.index("sid:") + 4
                        sid_str = ""
                        for c in line[sid_start:]:
                            if c.isdigit():
                                sid_str += c
                            else:
                                break
                        if sid_str:
                            self._existing_sids.add(int(sid_str))
                    # 预计算 content 指纹用于去重
                    fp = self._extract_content_fingerprint(line)
                    if fp:
                        self._existing_core_features.add(fp)
        except Exception as e:
            logger.warning("加载已有规则失败: %s", e)

    def _next_sid(self) -> int:
        """获取下一个可用 SID"""
        if self._existing_sids:
            return max(self._existing_sids) + 1
        return self.SID_MIN

    def _is_duplicate(self, rule: str) -> bool:
        """检查规则是否与已有规则检测同一攻击特征

        去重策略：提取所有 content 字段值，递归解码（URL/HTML/Base64/Hex）
        + 小写归一化后组成排序集合作为指纹。指纹完全相同才判重复。
        
        这种方式能识别 LLM 生成的编码变体（..%2f vs ../）和大小写变体
        （UNION vs union），同时不会误删检测不同攻击手法的规则
        （如路径遍历 vs PHP伪协议LFI，虽然都含 /etc/passwd 但 content
        组合不同）。
        """
        new_fingerprint = self._extract_content_fingerprint(rule)
        if not new_fingerprint:
            # 无 content 的规则回退到完全匹配
            return rule in self._existing_rules

        if new_fingerprint in self._existing_core_features:
            logger.info("规则 content 指纹重复，跳过: %s", new_fingerprint[:60])
            return True

        return False

    @staticmethod
    def _normalize_content(content: str) -> str:
        """归一化 content：递归解码（URL/HTML/Base64/Hex）+ 小写

        复用 attack_detector.recursive_decode 的解码能力，将 LLM 生成的
        各种编码变体统一到原始攻击载荷：
        - ..%2f / ..%252f / ..%25252f → ../（多层 URL 编码）
        - &#99;&#97;&#116; → cat（HTML 实体编码）
        - UNION / Union → union（大小写归一化）
        - 0x636174 → cat（Hex 编码）
        """
        from ..attack_detector import recursive_decode
        decoded = recursive_decode(content, max_depth=5)
        return decoded.lower().strip()

    def _extract_content_fingerprint(self, rule: str) -> str:
        """提取规则的 content 指纹（归一化后所有 content 的排序集合）

        用所有 content 组成指纹而非只取最长 content，避免误判：
        - 规则A: content="/etc/passwd" + content="../../../"  → 路径遍历
        - 规则B: content="/etc/passwd" + content="php://filter" → PHP伪协议LFI
        两者最长 content 相同（/etc/passwd）但 content 集合不同，指纹不同，
        不会被误判为重复。
        """
        contents = self._extract_contents(rule)
        if not contents:
            return ""
        normalized = sorted(self._normalize_content(c) for c in contents)
        return "|".join(normalized)

    @staticmethod
    def _extract_contents(rule: str) -> list:
        """提取 Suricata 规则中所有 content 字段的值"""
        contents = re.findall(r'content:"([^"]*)"', rule)
        return [c for c in contents if c]

    # 已知的通用宽泛字符串，单独使用时极易误报
    BROAD_PATTERNS = {
        "<?php", "<script", "eval", "exec", "system",
        "GET", "POST", "union", "select", "from",
    }

    def _is_too_broad(self, rule: str) -> bool:
        """检查规则是否过于宽泛（单个短 content 或通用字符串）"""
        contents = self._extract_contents(rule)
        has_pcre = "pcre:" in rule

        # 只有 1 个 content 且没有 pcre 时，检查是否过于宽泛
        if len(contents) == 1 and not has_pcre:
            c = contents[0]
            # 十六进制编码的 content 解码后检查
            decoded = self._decode_hex_content(c)
            # content 原文或解码后少于 10 字节
            if len(decoded) < 10:
                logger.warning("单个 content 过短 (%d bytes): %s", len(decoded), c[:40])
                return True
            # 解码后是通用宽泛字符串
            if decoded.lower() in self.BROAD_PATTERNS:
                logger.warning("单个 content 是通用宽泛字符串: %s", decoded)
                return True

        return False

    @staticmethod
    def _decode_hex_content(content: str) -> str:
        """解码 Suricata 管道符十六进制 content"""
        # |3c 3f 70 68 70| → <?php
        def replace_hex(match):
            hex_str = match.group(1)
            return bytes.fromhex(hex_str.replace(" ", "")).decode("utf-8", errors="replace")

        return re.sub(r'\|([0-9a-fA-F ]+)\|', replace_hex, content)

    @staticmethod
    def _has_invalid_hex(rule: str) -> bool:
        """检查规则中是否有无效的十六进制编码

        Suricata 要求 |...| 内的每个字节必须是 2 位十六进制，
        不能混用 ASCII 字符（如 |3c 3f php|）或单 digit（如 |a|）。
        """
        hex_segments = re.findall(r'\|([^|]+)\|', rule)
        for seg in hex_segments:
            parts = seg.split()
            for part in parts:
                if len(part) != 2 or not all(c in '0123456789abcdefABCDEF' for c in part):
                    return True
        return False

    @staticmethod
    def _validate_rule_structure(rule: str) -> bool:
        """检查规则基本结构（快速预检，在 suricata -T 之前拦截明显错误）"""
        parts = rule.split()
        if not parts:
            return False
        if parts[0].lower() not in {"alert", "drop", "reject", "pass"}:
            logger.warning("规则动作无效: %s", parts[0])
            return False
        if rule.count("(") != rule.count(")"):
            logger.warning("规则括号不匹配: (=%d, )=%d", rule.count("("), rule.count(")"))
            return False
        if "msg:" not in rule:
            logger.warning("规则缺少 msg 字段")
            return False
        return True

    @staticmethod
    def _sanitize_content_quotes(rule: str) -> str:
        """转义 content 字段内的裸双引号为 hex |22|

        Suricata 规则语法 content:"value" 的 value 内不允许裸双引号，
        必须用 |22| (hex) 转义。AI 生成的规则常忘记转义，导致 Suricata
        解析时 content 提前结束，规则加载失败。

        策略：找到 content:" 开始后，把值中所有非 hex 段内的双引号转义为 |22|，
        直到遇到 "; 或 ", 或 ") 或行尾作为 content 结束标志。
        对于 content 值内本身包含 "; 的情况（Suricata 无法正确解析），
        该规则将被截断但 Suricata 不会报错——截断后的 content 仍能子串匹配。
        """
        result = []
        i = 0
        n = len(rule)
        while i < n:
            # 检测 content:" 开始
            if rule[i:i+9] == 'content:"':
                result.append('content:"')
                i += 9
                in_hex = False
                while i < n:
                    c = rule[i]
                    if c == '|':
                        in_hex = not in_hex
                        result.append(c)
                        i += 1
                    elif c == '"' and not in_hex:
                        # 判断是否为 content 结束（后面跟 ; , ) 或行尾）
                        next_c = rule[i + 1] if i + 1 < n else ''
                        if next_c in ';,)' or i + 1 >= n:
                            result.append('"')
                            i += 1
                            break
                        else:
                            # 裸双引号，转义为 hex
                            result.append('|22|')
                            i += 1
                    else:
                        result.append(c)
                        i += 1
            else:
                result.append(rule[i])
                i += 1
        sanitized = ''.join(result)
        if sanitized != rule:
            logger.info("规则 content 双引号已转义: %s", rule[:80])
        return sanitized

    def write_rule(self, rule: str) -> bool:
        """写入一条规则到 local.rules

        Args:
            rule: Suricata 规则字符串

        Returns:
            True=写入成功, False=跳过（重复或无效）
        """
        rule = rule.strip()
        if not rule:
            return False

        # 转义 content 字段内的裸双引号，防止 Suricata 解析失败
        rule = self._sanitize_content_quotes(rule)

        # 快速结构预检：括号匹配、动作合法、必要字段
        if not self._validate_rule_structure(rule):
            logger.warning("规则结构无效，跳过: %s", rule[:80])
            return False

        with _write_lock:
            # 去重检查（在锁内执行，防止并发漏检）
            if self._is_duplicate(rule):
                logger.info("规则已存在，跳过: %s", rule[:80])
                return False

            # 宽泛规则拦截：单个短 content 容易误报
            if self._is_too_broad(rule):
                logger.warning("规则过于宽泛，跳过写入: %s", rule[:80])
                return False

            # 无效十六进制编码拦截：如 |3c 3f php| 或 |a|
            if self._has_invalid_hex(rule):
                logger.warning("规则包含无效的十六进制编码，跳过写入: %s", rule[:80])
                return False

            # 始终用唯一 SID 覆盖 AI 提供的 SID（AI 常照抄示例中的 9000001）
            new_sid = self._next_sid()
            if "sid:" in rule:
                rule = re.sub(r'sid:\d+', f'sid:{new_sid}', rule)
            else:
                # 无 SID 时在 rev 前或行尾插入
                if "rev:" in rule:
                    rule = rule.replace("rev:", f"sid:{new_sid}; rev:")
                else:
                    rule = rule.rstrip(");") + f"; sid:{new_sid};)"

            logger.info("分配 SID=%d: %s", new_sid, rule[:80])

            # 写入文件
            try:
                with open(self.rules_file, "a") as f:
                    f.write(rule + "\n")
                self._existing_rules.add(rule)
                self._existing_sids.add(new_sid)
                # 同步更新 content 指纹集合
                fp = self._extract_content_fingerprint(rule)
                if fp:
                    self._existing_core_features.add(fp)

                logger.info("规则已写入 local.rules: %s", rule[:80])
                return True
            except Exception as e:
                logger.error("写入规则失败: %s", e)
                return False

    def reload_suricata(self) -> bool:
        """验证规则语法 → 自动注释错误规则 → 热加载

        流程:
        1. 在 suricata 容器内运行 suricata -T 验证 local.rules
        2. 如有语法错误，解析出错行号并自动注释（最多重试 3 轮）
        3. 验证通过后执行 suricatasc -c reload-rules

        Returns:
            True=加载成功, False=加载失败
        """
        try:
            # Step 1: 验证并自愈（持写锁，防止并发写入干扰）
            with _write_lock:
                for attempt in range(3):
                    ok, bad_lines = self._test_rules_with_suricata()
                    if ok:
                        break
                    if not bad_lines:
                        logger.error("规则验证失败但无法定位错误行号，跳过自愈")
                        break
                    deleted = self._delete_bad_rules(bad_lines)
                    if deleted == 0:
                        break
                    logger.info("第 %d 轮验证：删除了 %d 条错误规则", attempt + 1, deleted)

            # Step 2: 热加载（无需写锁，仅 Docker exec）
            exit_code, output = self._exec_in_suricata([
                "suricatasc", "-c", "reload-rules",
            ])
            if exit_code != 0:
                logger.error("suricatasc 退出码 %d: %s", exit_code, output[:200])
                return False
            logger.info("Suricata 规则热加载成功")
            return True
        except Exception as e:
            logger.error("Suricata 热加载失败: %s", e)
            return False

    def _exec_in_suricata(self, cmd: list, timeout: int = 180) -> tuple:
        """通过 Docker Engine API 在 suricata 容器内执行命令

        Returns:
            (exit_code, output) — exit_code=-1 表示执行失败
        """
        sock_path = "/var/run/docker.sock"
        if not os.path.exists(sock_path):
            logger.error("Docker socket 不存在: %s", sock_path)
            return -1, ""

        try:
            with httpx.Client(transport=httpx.HTTPTransport(uds=sock_path), timeout=timeout) as client:
                # 1. 创建 exec 实例
                resp = client.post(
                    f"http://docker/containers/{self.suricata_container}/exec",
                    json={"AttachStdout": True, "AttachStderr": True, "Cmd": cmd},
                )
                if resp.status_code != 201:
                    logger.error("创建 exec 失败 (HTTP %d): %s", resp.status_code, resp.text)
                    return -1, ""

                exec_id = resp.json().get("Id")
                if not exec_id:
                    logger.error("exec 响应无 Id: %s", resp.text)
                    return -1, ""

                # 2. 启动 exec（同步等待输出）
                resp = client.post(
                    f"http://docker/exec/{exec_id}/start",
                    json={"Detach": False, "Tty": False},
                )
                if resp.status_code != 200:
                    logger.error("启动 exec 失败 (HTTP %d): %s", resp.status_code, resp.text)
                    return -1, ""

                # 输出在 /start 的响应中，必须在此处捕获
                output = self._parse_docker_stream(resp.content if hasattr(resp, 'content') else b"")

                # 3. 获取退出码
                resp = client.get(f"http://docker/exec/{exec_id}/json")
                exit_code = resp.json().get("ExitCode", -1) if resp.status_code == 200 else -1

                return exit_code, output
        except Exception as e:
            logger.error("Docker exec 失败: %s", e)
            return -1, ""

    def _test_rules_with_suricata(self) -> tuple:
        """使用 suricata -T 验证 local.rules 全部规则

        在 suricata 容器内运行 suricata -T -c suricata.yaml -S local.rules，
        利用 Suricata 自身的解析器做最严格的语法检查，能覆盖所有 Python
        层面无法预检的边界情况（如 content 内裸 |、pcre 语法错误等）。

        Returns:
            (ok, bad_line_numbers) — ok=True 表示全部通过
        """
        exit_code, output = self._exec_in_suricata([
            "suricata", "-T",
            "-c", "/etc/suricata/suricata.yaml",
            "-S", "/var/lib/suricata/rules/local.rules",
            "-l", "/tmp",
        ], timeout=120)

        if exit_code == 0:
            logger.info("Suricata 规则验证通过 (suricata -T)")
            return True, set()

        # 解析错误输出，提取出错行号
        # Suricata 8 格式: "from file /path at line 37"
        # 旧版格式: "from line 37 of /path"
        bad_lines = set()
        for match in re.finditer(r'(?:from line |at line )(\d+)', output):
            bad_lines.add(int(match.group(1)))

        logger.warning(
            "Suricata 规则验证失败 (exit=%d), %d 条规则有语法错误: %s",
            exit_code, len(bad_lines), output[:500],
        )
        return False, bad_lines

    def _delete_bad_rules(self, bad_lines: set) -> int:
        """删除指定行号的语法错误规则

        Args:
            bad_lines: 1-based 行号集合

        Returns:
            实际删除的规则数量
        """
        if not bad_lines:
            return 0

        try:
            with open(self.rules_file, "r") as f:
                lines = f.readlines()

            new_lines = []
            deleted = 0
            for i, line in enumerate(lines):
                line_num = i + 1
                if line_num in bad_lines and not line.strip().startswith("#"):
                    deleted += 1
                    logger.warning("删除语法错误规则 (line %d): %s", line_num, line.strip()[:80])
                else:
                    new_lines.append(line)

            if deleted > 0:
                with open(self.rules_file, "w") as f:
                    f.writelines(new_lines)
                logger.info("已删除 %d 条语法错误规则", deleted)
                # 删除后刷新内存状态，避免误判重复
                self._refresh_existing()

            return deleted
        except Exception as e:
            logger.error("删除错误规则失败: %s", e)
            return 0

    def _refresh_existing(self):
        """重新加载文件状态（删除规则后调用）"""
        self._existing_sids.clear()
        self._existing_rules.clear()
        self._existing_core_features.clear()
        self._load_existing()

    @staticmethod
    def _parse_docker_stream(data: bytes) -> str:
        """解析 Docker exec 的 multiplexed stream 输出"""
        if not data:
            return ""
        try:
            # Docker stream: [type(1byte)][size(4bytes)][data]
            # 跳过 header 直接提取文本
            result = []
            offset = 0
            while offset + 8 <= len(data):
                stream_type = data[offset]
                size = int.from_bytes(data[offset + 1:offset + 5], "big")
                offset += 8
                if offset + size > len(data):
                    chunk = data[offset:]
                else:
                    chunk = data[offset:offset + size]
                result.append(chunk.decode("utf-8", errors="replace"))
                offset += size
            return "".join(result)
        except Exception:
            return data.decode("utf-8", errors="replace")

    def write_and_reload(self, rule: str) -> dict:
        """写入规则并热加载

        Returns:
            {"written": bool, "reloaded": bool, "message": str}
        """
        written = self.write_rule(rule)

        if not written:
            return {"written": False, "reloaded": False, "message": "规则已存在或无效，跳过"}

        reloaded = self.reload_suricata()
        if reloaded:
            return {"written": True, "reloaded": True, "message": "规则已写入并热加载"}
        else:
            return {"written": True, "reloaded": False, "message": "规则已写入，但热加载失败（需手动重启 suricata）"}

    def write_only(self, rule: str) -> dict:
        """仅写入规则，不热加载（用于批量写入后统一热加载）

        Returns:
            {"written": bool, "message": str}
        """
        written = self.write_rule(rule)
        if written:
            return {"written": True, "message": "规则已写入（未热加载）"}
        return {"written": False, "message": "规则已存在或无效，跳过"}

    def reload_rules(self) -> dict:
        """热加载规则（批量写入后调用一次）

        Returns:
            {"reloaded": bool, "message": str}
        """
        reloaded = self.reload_suricata()
        if reloaded:
            return {"reloaded": True, "message": "规则热加载成功"}
        return {"reloaded": False, "message": "热加载失败（需手动重启 suricata）"}
