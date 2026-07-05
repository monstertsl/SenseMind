"""ES 只读查询客户端 —— 使用 API Key 访问 ES

使用专用 API Key（sensemind-reader）的原因：
- API Key 仅授予 soc-* / soc-ai-* 索引的只读权限，最小化权限
- 避免查询 API 直接持有 elastic 密码（写入场景仍用 elastic）
- API Key 可独立撤销/轮换，不影响其他服务
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch
from ..config import Config

logger = logging.getLogger(__name__)


class ESReader:
    """ES 只读客户端，单例"""

    _instance = None
    _client = None

    def __new__(cls):
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._init_client()
            cls._instance = instance
        return cls._instance

    def _init_client(self):
        cfg = Config()
        es_cfg = cfg.elasticsearch
        headers = {"Accept": "application/vnd.elasticsearch+json; compatible-with=8"}
        # 优先使用 API Key 认证（专用只读 key，仅授权 soc-* / soc-ai-* 索引）
        api_key = os.environ.get("ES_READER_API_KEY", "")
        if api_key:
            self._client = Elasticsearch(
                es_cfg["hosts"],
                headers=headers,
                api_key=api_key,
                request_timeout=30,
                verify_certs=True,
                ca_certs=es_cfg.get("ca_cert"),
            )
            logger.info("ESReader 使用 API Key 鉴权（sensemind-reader）")
        else:
            # 降级：API Key 未配置时回退到 basic_auth
            self._client = Elasticsearch(
                es_cfg["hosts"],
                headers=headers,
                basic_auth=(es_cfg.get("username", "elastic"), cfg.es_password),
                request_timeout=30,
                verify_certs=True,
                ca_certs=es_cfg.get("ca_cert"),
            )
            logger.warning("ESReader 降级使用 basic_auth（建议配置 ES_READER_API_KEY）")

    @property
    def client(self) -> Elasticsearch:
        return self._client

    @property
    def ai_index(self) -> str:
        return "soc-ai-*"

    @property
    def source_index(self) -> str:
        return "soc-*"

    def time_range_to_iso(self, time_range: str) -> tuple[str, str]:
        """时间粒度转 ISO 区间"""
        now = datetime.now(timezone.utc)
        mapping = {
            "today": (now.replace(hour=0, minute=0, second=0, microsecond=0), now),
            "yesterday": (
                (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0),
                (now - timedelta(days=1)).replace(hour=23, minute=59, second=59),
            ),
            "7d": (now - timedelta(days=7), now),
            "30d": (now - timedelta(days=30), now),
        }
        f, t = mapping.get(time_range, mapping["7d"])
        return f.isoformat(), t.isoformat()


def get_es_reader() -> ESReader:
    return ESReader()
