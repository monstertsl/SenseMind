"""配置加载模块"""

import os
import yaml
from pathlib import Path
from datetime import datetime


class Config:
    """全局配置单例"""

    _instance = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load()
        return cls._instance

    def _load(self):
        config_path = os.environ.get(
            "AI_CONFIG_PATH",
            str(Path(__file__).resolve().parent.parent / "config.yaml"),
        )
        with open(config_path, "r", encoding="utf-8") as f:
            self._config = yaml.safe_load(f)

    @property
    def llm(self) -> dict:
        return self._config["llm"]

    @property
    def elasticsearch(self) -> dict:
        return self._config["elasticsearch"]

    @property
    def webhook(self) -> dict:
        return self._config["webhook"]

    @property
    def knowledge_dir(self) -> str:
        """知识库目录路径（RAG 检索源）"""
        return self._config.get("knowledge", {}).get(
            "dir", "/usr/share/ai-analyzer/knowledge"
        )

    @property
    def suricata(self) -> dict:
        """Suricata 规则自动生成配置"""
        return self._config.get("suricata", {
            "enabled": False,
            "rules_file": "/suricata/rules/local.rules",
            "suricata_container": "suricata",
        })

    @property
    def dedup(self) -> dict:
        """告警去重配置"""
        return self._config.get("dedup", {
            "enabled": True,
            "window_seconds": 600,
            "max_entries": 10000,
        })

    @property
    def es_password(self) -> str:
        """从环境变量获取 ES 密码"""
        env_key = self.elasticsearch.get("password_env", "ELASTIC_PASSWORD")
        return os.environ.get(env_key, "")

    def get_result_index(self) -> str:
        """获取当天的结果索引名"""
        template = self.elasticsearch.get("result_index", "soc-ai-%{date}")
        return template.replace("%{date}", datetime.now().strftime("%Y.%m.%d"))
