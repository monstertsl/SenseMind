"""日志中心路由 —— 检索/详情/Mapping/校验"""

import uuid
from fastapi import APIRouter, Depends, Query
from ..core.auth import AuthContext, get_current_user
from ..schemas import ApiResponse, LogSearchBody, ExportBody
from ..services.log_service import get_log_service

router = APIRouter(prefix="/api/v1", tags=["logs"])


@router.post("/logs/search")
def search_logs(body: LogSearchBody, current_user: AuthContext = Depends(get_current_user)):
    service = get_log_service()
    data = service.search(body)
    return ApiResponse(
        code=0, message="ok", data=data.model_dump(by_alias=True, mode="json"),
        request_id=str(uuid.uuid4()),
    )


@router.get("/logs/mapping")
def get_mapping(
    indices: str = Query(None),
    current_user: AuthContext = Depends(get_current_user),
):
    idx_list = indices.split(",") if indices else None
    service = get_log_service()
    data = service.get_mapping(idx_list)
    return ApiResponse(
        code=0, message="ok", data=data.model_dump(), request_id=str(uuid.uuid4())
    )


@router.post("/logs/export")
def export_logs(body: ExportBody, current_user: AuthContext = Depends(get_current_user)):
    # 一期返回 task_id 占位（异步导出后续实现）
    return ApiResponse(
        code=0, message="ok",
        data={"task_id": str(uuid.uuid4())},
        request_id=str(uuid.uuid4()),
    )


@router.get("/logs/{doc_id}")
def get_log(
    doc_id: str,
    index: str = Query(...),
    current_user: AuthContext = Depends(get_current_user),
):
    service = get_log_service()
    try:
        data = service.get_log(doc_id, index)
        return ApiResponse(code=0, message="ok", data=data, request_id=str(uuid.uuid4()))
    except Exception as e:
        return ApiResponse(code=404, message=f"日志不存在: {e}", data=None, request_id=str(uuid.uuid4()))


@router.get("/system/validate-mapping")
def validate_mapping(current_user: AuthContext = Depends(get_current_user)):
    service = get_log_service()
    data = service.validate_mapping()
    return ApiResponse(code=0, message="ok", data=data, request_id=str(uuid.uuid4()))
