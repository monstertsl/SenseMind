"""系统信息路由 —— CPU / 内存 / 磁盘占用"""

import uuid
from fastapi import APIRouter, Depends, Request
from ..core.auth import AuthContext, get_current_user
from ..schemas import ApiResponse
from ..services.system_service import get_system_service

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
