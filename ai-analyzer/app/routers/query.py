"""分析中心路由 —— 告警查询/详情/聚合"""

import logging
import uuid
from elasticsearch import BadRequestError
from fastapi import APIRouter, Depends, HTTPException, Query
from ..core.auth import AuthContext, get_current_user
from ..schemas import ApiResponse, AlertQueryParams
from ..services.query_service import get_query_service
from ..suricata.rule_lookup import get_rule_lookup

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


def _bad_request_reason(exc: BadRequestError) -> str:
    """取 ES 报错根因，便于把 KQL 语法错误回给前端"""
    try:
        return exc.info["error"]["root_cause"][0]["reason"]
    except (KeyError, IndexError, TypeError, AttributeError):
        return str(exc)


@router.get("")
def list_alerts(
    time_range: str = Query("today"),
    time_from: str = Query(None),
    time_to: str = Query(None),
    source_ip: str = Query(None),
    destination_ip: str = Query(None),
    soc_name: str = Query(None),
    threat_verdict: str = Query(None),
    confidence: float = Query(None),
    confidence_min: float = Query(None),
    confidence_max: float = Query(None),
    alert_signature: str = Query(None),
    source_alert_id: str = Query(None),
    attack_result: str = Query(None),
    kql: str = Query(None),
    exclude_source_ip: str = Query(None),
    exclude_destination_ip: str = Query(None),
    exclude_alert_signature: str = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    sort_field: str = Query("ai.alert_timestamp"),
    sort_order: str = Query("desc"),
    current_user: AuthContext = Depends(get_current_user),
):
    params = AlertQueryParams(
        time_range=time_range, time_from=time_from, time_to=time_to,
        source_ip=source_ip, destination_ip=destination_ip, soc_name=soc_name,
        threat_verdict=threat_verdict,
        confidence=confidence, confidence_min=confidence_min, confidence_max=confidence_max,
        alert_signature=alert_signature,
        source_alert_id=source_alert_id, attack_result=attack_result,
        kql=kql,
        exclude_source_ip=exclude_source_ip,
        exclude_destination_ip=exclude_destination_ip,
        exclude_alert_signature=exclude_alert_signature,
        page=page, page_size=page_size,
        sort_field=sort_field, sort_order=sort_order,
    )
    service = get_query_service()
    try:
        data = service.list_alerts(params)
    except BadRequestError as e:
        # 参数类错误（KQL 语法等）重试无意义，直接回 400 让前端提示
        reason = _bad_request_reason(e)
        logger.warning("告警查询被 ES 拒绝: %s", reason)
        raise HTTPException(
            status_code=400,
            detail=f"检索条件无法解析，请检查 KQL 语法（{reason}）",
        )
    return ApiResponse(
        code=0, message="ok",
        data=data.model_dump(by_alias=True, mode="json"),
        request_id=str(uuid.uuid4()),
    )


@router.get("/aggregations")
def aggregations(
    field: str = Query(...),
    time_range: str = Query("7d"),
    time_from: str = Query(None),
    time_to: str = Query(None),
    current_user: AuthContext = Depends(get_current_user),
):
    service = get_query_service()
    data = service.aggregations(field, time_range, time_from, time_to)
    return ApiResponse(
        code=0, message="ok", data=data.model_dump(), request_id=str(uuid.uuid4())
    )


# 必须定义在 /{doc_id} 之前：FastAPI 按注册顺序匹配，否则会被当作 doc_id
@router.get("/rule-contents")
def rule_contents(
    sid: int = Query(..., ge=1),
    current_user: AuthContext = Depends(get_current_user),
):
    """按 sid 返回规则的 content 字面量，供详情高亮命中片段"""
    return ApiResponse(
        code=0, message="ok",
        data=get_rule_lookup().get(sid),
        request_id=str(uuid.uuid4()),
    )


@router.get("/{doc_id}")
def get_alert(doc_id: str, current_user: AuthContext = Depends(get_current_user)):
    service = get_query_service()
    data = service.get_alert(doc_id)
    if data is None:
        return ApiResponse(code=404, message="告警不存在", data=None, request_id=str(uuid.uuid4()))
    return ApiResponse(code=0, message="ok", data=data, request_id=str(uuid.uuid4()))
