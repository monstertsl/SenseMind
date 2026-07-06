"""分析中心路由 —— 告警查询/详情/聚合"""

import uuid
from fastapi import APIRouter, Depends, Query
from ..core.auth import AuthContext, get_current_user
from ..schemas import ApiResponse, AlertQueryParams
from ..services.query_service import get_query_service

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("")
def list_alerts(
    time_range: str = Query("today"),
    time_from: str = Query(None),
    time_to: str = Query(None),
    source_ip: str = Query(None),
    destination_ip: str = Query(None),
    soc_name: str = Query(None),
    confidence: float = Query(None),
    alert_signature: str = Query(None),
    source_alert_id: str = Query(None),
    attack_result: str = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    sort_field: str = Query("ai.alert_timestamp"),
    sort_order: str = Query("desc"),
    current_user: AuthContext = Depends(get_current_user),
):
    params = AlertQueryParams(
        time_range=time_range, time_from=time_from, time_to=time_to,
        source_ip=source_ip, destination_ip=destination_ip, soc_name=soc_name,
        confidence=confidence, alert_signature=alert_signature,
        source_alert_id=source_alert_id, attack_result=attack_result,
        page=page, page_size=page_size,
        sort_field=sort_field, sort_order=sort_order,
    )
    service = get_query_service()
    data = service.list_alerts(params)
    return ApiResponse(
        code=0, message="ok",
        data=data.model_dump(by_alias=True, mode="json"),
        request_id=str(uuid.uuid4()),
    )


@router.get("/aggregations")
def aggregations(
    field: str = Query(...),
    time_range: str = Query("7d"),
    current_user: AuthContext = Depends(get_current_user),
):
    service = get_query_service()
    data = service.aggregations(field, time_range)
    return ApiResponse(
        code=0, message="ok", data=data.model_dump(), request_id=str(uuid.uuid4())
    )


@router.get("/{doc_id}")
def get_alert(doc_id: str, current_user: AuthContext = Depends(get_current_user)):
    service = get_query_service()
    data = service.get_alert(doc_id)
    if data is None:
        return ApiResponse(code=404, message="告警不存在", data=None, request_id=str(uuid.uuid4()))
    return ApiResponse(code=0, message="ok", data=data, request_id=str(uuid.uuid4()))
