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
        except Exception as e:
            logger.warning("加载已有规则失败: %s", e)

    def _next_sid(self) -> int:
        """获取下一个可用 SID"""
        if self._existing_sids:
            return max(self._existing_sids) + 1
        return self.SID_MIN

    def _is_duplicate(self, rule: str) -> bool:
        """检查规则是否与已有规则检测同一攻击特征

        去重策略：提取所有 content 字段值并排序，完全相同才判重复。
        不做子串推断——content 的精度差异由 AI 在生成时控制，
        用子串包含会误判（如 "GET" 吞噬 "GET /attack"）。
        """
        new_contents = self._extract_contents(rule)
        if not new_contents:
            return False

        new_key = tuple(sorted(new_contents))

        for existing in self._existing_rules:
            existing_contents = self._extract_contents(existing)
            if not existing_contents:
                continue
            if new_key == tuple(sorted(existing_contents)):
                logger.info("规则 content 特征重复，跳过")
                return True

        return False

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

                logger.info("规则已写入 local.rules: %s", rule[:80])
                return True
            except Exception as e:
                logger.error("写入规则失败: %s", e)
                return False

    def reload_suricata(self) -> bool:
        """通过 Docker Engine API 热加载规则

        直接调用 /var/run/docker.sock 的 exec 接口，在 suricata 容器内
        执行 suricatasc -c reload-rules，无需 docker CLI。

        Returns:
            True=加载成功, False=加载失败
        """
        try:
            return self._reload_via_docker_api()
        except Exception as e:
            logger.error("Suricata 热加载失败: %s", e)
            return False

    def _reload_via_docker_api(self) -> bool:
        """通过 Docker Engine socket API 执行热加载"""
        sock_path = "/var/run/docker.sock"
        if not os.path.exists(sock_path):
            logger.error("Docker socket 不存在: %s", sock_path)
            return False

        base_url = "http+unix://" + sock_path.replace("/", "%2F")

        # 1. 创建 exec 实例
        exec_payload = {
            "AttachStdout": True,
            "AttachStderr": True,
            "Cmd": ["suricatasc", "-c", "reload-rules"],
        }

        with httpx.Client(transport=httpx.HTTPTransport(uds=sock_path), timeout=30) as client:
            resp = client.post(
                f"http://docker/containers/{self.suricata_container}/exec",
                json=exec_payload,
            )
            if resp.status_code != 201:
                logger.error("创建 exec 失败 (HTTP %d): %s", resp.status_code, resp.text)
                return False

            exec_id = resp.json().get("Id")
            if not exec_id:
                logger.error("exec 响应无 Id: %s", resp.text)
                return False

            # 2. 启动 exec（同步等待输出）
            resp = client.post(
                f"http://docker/exec/{exec_id}/start",
                json={"Detach": False, "Tty": False},
            )
            if resp.status_code != 200:
                logger.error("启动 exec 失败 (HTTP %d): %s", resp.status_code, resp.text)
                return False

            # 3. 检查 exec 退出码
            resp = client.get(f"http://docker/exec/{exec_id}/json")
            if resp.status_code == 200:
                exit_code = resp.json().get("ExitCode", -1)
                if exit_code != 0:
                    logger.error("suricatasc 退出码 %d", exit_code)
                    return False

            # 4. 解析输出（Docker stream 格式，前 8 字节为 header）
            output = self._parse_docker_stream(resp.content if hasattr(resp, 'content') else b"")
            # start 的响应 body 才是实际输出，重新获取
            # 上面的 /json 返回的是元数据，输出在 /start 的响应中
            # 需要重新调用 start 获取输出 - 但 exec 已执行完毕
            # 改用 inspect 获取输出不可行，输出在 start 响应中

            # 简化：只要退出码为 0 即认为成功
            logger.info("Suricata 规则热加载成功 (exec=%s)", exec_id)
            return True

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
