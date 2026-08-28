"""系统信息路由 —— CPU / 内存 / 磁盘占用 + 资源时序数据"""

import uuid
from fastapi import APIRouter, Depends, Query, Request
from ..core.auth import AuthContext, get_current_user
from ..schemas import ApiResponse
from ..services.system_service import get_system_service
from ..services.metric_query import query_metrics

router = APIRouter(prefix="/api/v1/system", tags=["system"])


@router.get("/info")
def system_info(current_user: AuthContext = Depends(get_current_user)):
    service = get_system_service()
    data = service.get_info()
    return ApiResponse(
        code=0, message="ok",
        data=data.model_dump(),
        request_id=str(uuid.uuid4()),
    )


@router.get("/metrics")
def system_metrics(
    range: str = Query("24h"),
    current_user: AuthContext = Depends(get_current_user),
):
    """系统资源时序数据（趋势图用）。

    range: 1h（5秒原始点）/ 24h（2分钟桶）/ 7d（30分钟桶）
    丢包用 SUM 聚合，CPU/内存/流量用 AVG（附带 max）。
    """
    if range not in ("1h", "24h", "7d"):
        range = "24h"
    data = query_metrics(range)
    return ApiResponse(
        code=0, message="ok",
        data=data,
        request_id=str(uuid.uuid4()),
    )


@router.get("/client-ip")
def get_client_ip(request: Request, current_user: AuthContext = Depends(get_current_user)):
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "unknown"
    return ApiResponse(
        code=0, message="ok",
        data={"ip": client_ip},
        request_id=str(uuid.uuid4()),
    )
