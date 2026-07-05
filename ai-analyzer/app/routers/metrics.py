"""监测中心路由"""

import uuid
from fastapi import APIRouter, Depends, Query
from ..core.auth import AuthContext, get_current_user
from ..schemas import ApiResponse
from ..services.metrics_service import get_metrics_service

router = APIRouter(prefix="/api/v1/metrics", tags=["metrics"])


@router.get("/overview")
def metrics_overview(
    time_range: str = Query("7d"),
    current_user: AuthContext = Depends(get_current_user),
):
    service = get_metrics_service()
    data = service.overview(time_range)
    return ApiResponse(code=0, message="ok", data=data, request_id=str(uuid.uuid4()))
