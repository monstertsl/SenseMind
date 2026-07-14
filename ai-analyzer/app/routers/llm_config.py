"""LLM 配置路由 —— 系统设置 > 集成配置 > LLM 模型"""

import uuid
import logging
import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from typing import Optional

from ..core.database import get_db
from ..core.auth import require_role, get_current_user, AuthContext
from ..db_models.system_config import SystemConfig
from ..schemas import ApiResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/llm-config", tags=["LLM配置"])

# 固定默认值
_DEFAULT_TEMPERATURE = 0.1
_DEFAULT_MAX_TOKENS = 4000
_DEFAULT_TIMEOUT = 60


class LLMConfigUpdate(BaseModel):
    api_endpoint: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    timeout: Optional[int] = None


class LLMConfigResponse(BaseModel):
    api_endpoint: str
    api_key: str
    model: str
    temperature: float = _DEFAULT_TEMPERATURE
    max_tokens: int = _DEFAULT_MAX_TOKENS
    timeout: int = _DEFAULT_TIMEOUT


class LLMTestRequest(BaseModel):
    api_endpoint: str
    api_key: str = ""
    model: str = ""


def _get_or_create_config(db: Session) -> SystemConfig:
    cfg = db.execute(select(SystemConfig).where(SystemConfig.id == 1)).scalar_one_or_none()
    if not cfg:
        cfg = SystemConfig(id=1)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _cfg_to_llm_response(cfg: SystemConfig) -> LLMConfigResponse:
    return LLMConfigResponse(
        api_endpoint=cfg.llm_api_endpoint or "",
        api_key=cfg.llm_api_key or "",
        model=cfg.llm_model or "",
        temperature=cfg.llm_temperature if hasattr(cfg, 'llm_temperature') and cfg.llm_temperature else _DEFAULT_TEMPERATURE,
        max_tokens=cfg.llm_max_tokens if hasattr(cfg, 'llm_max_tokens') and cfg.llm_max_tokens else _DEFAULT_MAX_TOKENS,
        timeout=cfg.llm_timeout if hasattr(cfg, 'llm_timeout') and cfg.llm_timeout else _DEFAULT_TIMEOUT,
    )


def get_llm_config_from_db(db: Session = None) -> dict:
    """供 analyzer 调用：从 DB 读取 LLM 配置"""
    if db is None:
        from ..core.database import SessionLocal
        db = SessionLocal()
        try:
            return _read_llm(db)
        finally:
            db.close()
    return _read_llm(db)


def _read_llm(db: Session) -> dict:
    cfg = db.execute(select(SystemConfig).where(SystemConfig.id == 1)).scalar_one_or_none()
    if cfg and cfg.llm_api_endpoint:
        return {
            "api_key": cfg.llm_api_key or "",
            "base_url": cfg.llm_api_endpoint,
            "model": cfg.llm_model or "",
            "temperature": cfg.llm_temperature if hasattr(cfg, 'llm_temperature') and cfg.llm_temperature else _DEFAULT_TEMPERATURE,
            "max_tokens": cfg.llm_max_tokens if hasattr(cfg, 'llm_max_tokens') and cfg.llm_max_tokens else _DEFAULT_MAX_TOKENS,
            "timeout": cfg.llm_timeout if hasattr(cfg, 'llm_timeout') and cfg.llm_timeout else _DEFAULT_TIMEOUT,
        }
    return {
        "api_key": "",
        "base_url": "",
        "model": "",
        "temperature": _DEFAULT_TEMPERATURE,
        "max_tokens": _DEFAULT_MAX_TOKENS,
        "timeout": _DEFAULT_TIMEOUT,
    }


@router.get("", response_model=ApiResponse)
def get_llm_config(db: Session = Depends(get_db), current_user: AuthContext = Depends(require_role("admin"))):
    cfg = _get_or_create_config(db)
    return ApiResponse(code=0, message="ok",
                       data=_cfg_to_llm_response(cfg).model_dump(),
                       request_id=str(uuid.uuid4()))


@router.put("", response_model=ApiResponse)
def update_llm_config(body: LLMConfigUpdate, db: Session = Depends(get_db),
                      current_user: AuthContext = Depends(require_role("admin"))):
    cfg = _get_or_create_config(db)
    if body.api_endpoint is not None:
        cfg.llm_api_endpoint = body.api_endpoint.strip()
    if body.api_key is not None:
        cfg.llm_api_key = body.api_key.strip()
    if body.model is not None:
        cfg.llm_model = body.model.strip()
    if body.temperature is not None:
        cfg.llm_temperature = body.temperature
    if body.max_tokens is not None:
        cfg.llm_max_tokens = body.max_tokens
    if body.timeout is not None:
        cfg.llm_timeout = body.timeout
    db.commit()
    db.refresh(cfg)

    # 重新加载分析器以应用新的 LLM 配置
    try:
        from ..main import reload_analyzer
        reload_analyzer()
    except Exception as e:
        logger.warning("分析器重新加载失败（配置已保存）: %s", e)

    return ApiResponse(code=0, message="ok",
                       data=_cfg_to_llm_response(cfg).model_dump(),
                       request_id=str(uuid.uuid4()))


@router.post("/test", response_model=ApiResponse)
def test_llm_connection(body: LLMTestRequest, db: Session = Depends(get_db),
                        current_user: AuthContext = Depends(require_role("admin"))):
    """测试 LLM 连接是否正常

    策略：
    - 有 model：发送 chat/completions 请求测试
    - 无 model：发送 GET /models 请求测试连通性
    """
    endpoint = body.api_endpoint.strip()
    if not endpoint:
        raise HTTPException(status_code=400, detail="API Endpoint 不能为空")

    api_key = body.api_key.strip()
    model = body.model.strip()

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    base = endpoint.rstrip("/")

    try:
        with httpx.Client(timeout=15) as client:
            if model:
                # 有模型：发送简单的 chat completions 请求
                test_payload = {
                    "model": model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 5,
                    "temperature": 0,
                }
                resp = client.post(f"{base}/chat/completions", headers=headers, json=test_payload)
            else:
                # 无模型：检查 /models 端点连通性
                resp = client.get(f"{base}/models", headers=headers)

        if resp.status_code == 200:
            return ApiResponse(code=0, message="连接成功", data={"status": "ok"},
                               request_id=str(uuid.uuid4()))
        else:
            return ApiResponse(code=1,
                               message=f"连接失败 (HTTP {resp.status_code}): {resp.text[:300]}",
                               data=None, request_id=str(uuid.uuid4()))
    except Exception as e:
        logger.warning("LLM 连接测试失败: %s", e)
        return ApiResponse(code=1, message=f"连接异常: {e}", data=None,
                           request_id=str(uuid.uuid4()))


@router.get("/models", response_model=ApiResponse)
def list_models(
    endpoint: str = "",
    api_key: str = "",
    db: Session = Depends(get_db),
    current_user: AuthContext = Depends(get_current_user),
):
    """获取可用模型列表

    优先使用 query 参数中的 endpoint/api_key（支持未保存时获取），
    回退到 DB 中已保存的配置。
    """
    ep = endpoint.strip()
    key = api_key.strip()

    if not ep:
        # 回退到 DB
        cfg = _get_or_create_config(db)
        ep = cfg.llm_api_endpoint or ""
        key = cfg.llm_api_key or ""

    if not ep:
        return ApiResponse(code=0, message="ok", data=[], request_id=str(uuid.uuid4()))

    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(f"{ep.rstrip('/')}/models", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            models = []
            if isinstance(data, dict) and "data" in data:
                for m in data["data"]:
                    mid = m.get("id", "") if isinstance(m, dict) else str(m)
                    if mid:
                        models.append(mid)
            elif isinstance(data, list):
                for m in data:
                    mid = m.get("id", "") if isinstance(m, dict) else str(m)
                    if mid:
                        models.append(mid)
            models.sort()
            return ApiResponse(code=0, message="ok", data=models,
                               request_id=str(uuid.uuid4()))
        else:
            return ApiResponse(code=1, message=f"获取模型列表失败 (HTTP {resp.status_code})",
                               data=[], request_id=str(uuid.uuid4()))
    except Exception as e:
        logger.warning("获取模型列表失败: %s", e)
        return ApiResponse(code=1, message=f"获取模型列表异常: {e}",
                           data=[], request_id=str(uuid.uuid4()))
