"""Suricata 规则写入器

负责将 AI 生成的规则写入 local.rules 文件，
并通过 docker exec suricata suricatasc 热加载规则。

规则文件: /data/suricata/lib/rules/local.rules (宿主机)
          → /var/lib/suricata/rules/local.rules (suricata 容器)
          → /suricata/rules/local.rules (ai-analyzer 容器)

热加载: 通过 docker exec suricata suricatasc -c reload-rules
        利用 jasonish/suricata 镜像内置的 suricatasc 工具
"""

import logging
import os
import subprocess
import re

logger = logging.getLogger(__name__)


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
        """检查规则是否已存在（去除 SID 和 rev 后比较）"""
        # 去除 sid:xxx 和 rev:xxx 后比较
        normalized = re.sub(r'sid:\d+', 'sid:X', rule)
        normalized = re.sub(r'rev:\d+', 'rev:X', normalized)
        for existing in self._existing_rules:
            existing_norm = re.sub(r'sid:\d+', 'sid:X', existing)
            existing_norm = re.sub(r'rev:\d+', 'rev:X', existing_norm)
            if normalized == existing_norm:
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

        # 去重检查
        if self._is_duplicate(rule):
            logger.info("规则已存在，跳过: %s", rule[:80])
            return False

        # 确保 SID 在 AI 范围内
        if "sid:" not in rule:
            logger.warning("规则缺少 SID，跳过: %s", rule[:80])
            return False

        # 写入文件
        try:
            with open(self.rules_file, "a") as f:
                f.write(rule + "\n")
            self._existing_rules.add(rule)
            # 更新 SID 集合
            sid_start = rule.index("sid:") + 4
            sid_str = ""
            for c in rule[sid_start:]:
                if c.isdigit():
                    sid_str += c
                else:
                    break
            if sid_str:
                self._existing_sids.add(int(sid_str))

            logger.info("规则已写入 local.rules: %s", rule[:80])
            return True
        except Exception as e:
            logger.error("写入规则失败: %s", e)
            return False

    def reload_suricata(self) -> bool:
        """通过 docker exec suricata suricatasc 热加载规则

        jasonish/suricata 镜像内置 suricatasc 工具，
        通过 docker exec 在 suricata 容器内执行 reload-rules 命令。

        Returns:
            True=加载成功, False=加载失败
        """
        try:
            result = subprocess.run(
                ["docker", "exec", self.suricata_container,
                 "suricatasc", "-c", "reload-rules"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                # suricatasc 返回 JSON: {"return": "OK", "message": "..."}
                output = result.stdout.strip()
                if '"return": "OK"' in output or '"return":"OK"' in output:
                    logger.info("Suricata 规则热加载成功: %s", output)
                    return True
                else:
                    logger.warning("Suricata 热加载返回非OK: %s", output)
                    return False
            else:
                logger.error("suricatasc 执行失败 (exit=%d): %s",
                             result.returncode, result.stderr)
                return False
        except subprocess.TimeoutExpired:
            logger.error("suricatasc 执行超时")
            return False
        except FileNotFoundError:
            logger.error("docker 命令不可用（ai-analyzer 容器内未安装 docker CLI）")
            return False
        except Exception as e:
            logger.error("Suricata 热加载失败: %s", e)
            return False

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
