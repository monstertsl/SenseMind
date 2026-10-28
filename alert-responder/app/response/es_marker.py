"""告警处置标记：封堵成功后把原告警文档的 `blocked` 置为 true。

需求口径（`docs/联动外发需求.txt`）：

- `blocked=true` **仅封堵成功后写入**，处置失败不标记；
- 处置前查该标记，已标记的直接跳过（幂等）；
- 标记失败只记日志，不能反过来影响处置结果本身。

写权限走 ES 超级用户（`ES_PASSWORD` 由 compose 从 `ELASTIC_PASSWORD` 注入），
只读接口仍用 `ES_READER_API_KEY`。
"""

import logging
import os

from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)

ES_URL = os.environ.get("ES_URL", "https://elasticsearch:9200")
ES_USERNAME = os.environ.get("ES_USERNAME", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "")
ES_CA_CERT = os.environ.get("ES_CA_CERT", "")
# AI 分析结果索引：分析中心列表与筛选查的是这里，blocked 必须写在它上面
ES_RESULT_INDEX = os.environ.get("ES_RESULT_INDEX", "soc-ai-*")

_client: Elasticsearch | None = None


def _get_client() -> Elasticsearch:
    global _client
    if _client is None:
        _client = Elasticsearch(
            ES_URL,
            basic_auth=(ES_USERNAME, ES_PASSWORD),
            ca_certs=ES_CA_CERT or None,
            verify_certs=bool(ES_CA_CERT),
            request_timeout=10,
            headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8"},
        )
    return _client


def is_blocked(index: str, doc_id: str) -> bool:
    """处置前查标记；索引/ID 缺失或查询异常都按未标记处理。"""
    if not index or not doc_id:
        return False
    try:
        doc = _get_client().get(index=index, id=doc_id, source_includes=["blocked"])
    except Exception:
        return False
    return bool((doc.get("_source") or {}).get("blocked"))


def _update_doc(index: str, doc_id: str) -> bool:
    try:
        _get_client().update(index=index, id=doc_id, doc={"blocked": True}, refresh=True)
        return True
    except Exception as exc:
        logger.warning("标记 blocked 失败 index=%s id=%s：%s", index, doc_id, exc)
        return False


def _mark_results(alert_id: str) -> bool:
    """AI 结果文档没有反向指向自身，按 `ai.source_alert_id` 反查后批量打标。"""
    try:
        resp = _get_client().update_by_query(
            index=ES_RESULT_INDEX,
            query={"term": {"ai.source_alert_id": alert_id}},
            script={"source": "ctx._source.blocked = true", "lang": "painless"},
            refresh=True,
            conflicts="proceed",
        )
    except Exception as exc:
        logger.warning("标记分析结果 blocked 失败 alert_id=%s：%s", alert_id, exc)
        return False
    return int(resp.get("updated") or 0) > 0


def mark_blocked(index: str, doc_id: str) -> bool:
    """原告警与 AI 结果文档都写 `blocked=true`。

    返回值表示 **AI 结果文档**是否标记成功（分析中心的「是否处理」筛选与 KQL 都查它）；
    原告警文档标记失败只记日志。

    注意：`blocked` 必须在 soc-ai 索引模板的 properties 白名单里显式声明（deploy.sh 3.5.5）。
    模板的 dynamic_templates 会把动态布尔字段建成 index:false / doc_values:false，
    那样字段可写入但 term 查询会报 Cannot search on field [blocked]。
    """
    if not doc_id:
        logger.info("未提供告警文档 ID，跳过 blocked 标记")
        return False
    if index:
        _update_doc(index, doc_id)
    return _mark_results(doc_id)
