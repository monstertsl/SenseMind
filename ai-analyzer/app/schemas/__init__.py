"""Pydantic 请求/响应模型 —— 查询 API 层"""

from typing import Any, Optional, Union
from pydantic import BaseModel, ConfigDict, Field


# ---- 通用响应 ----
class ApiResponse(BaseModel):
    code: int = 0
    message: str = "ok"
    data: Any
    request_id: str = ""


# ---- 监测中心 ----
class MetricsOverviewData(BaseModel):
    risk_level: str
    total_alerts: int
    victim_assets: int
    attacker_count: int
    ai_total: int
    ai_victim_targets: int
    ai_attacker_ips: int
    ai_avg_confidence: float
    ai_confidence_prev: float
    soc_attack_distribution: list[dict]
    threat_verdict_distribution: dict
    threat_source_distribution: dict


# ---- 分析中心 ----
class AlertQueryParams(BaseModel):
    time_range: Optional[str] = "today"
    time_from: Optional[str] = None
    time_to: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    soc_name: Optional[str] = None
    confidence: Optional[float] = None
    alert_signature: Optional[str] = None
    source_alert_id: Optional[str] = None
    page: int = 1
    page_size: int = 20
    sort_field: str = "ai.alert_timestamp"
    sort_order: str = "desc"


class AlertItemData(BaseModel):
    # Pydantic v2 将 _ 开头字段视为私有属性，需用 alias + populate_by_name 使其正常序列化
    model_config = ConfigDict(populate_by_name=True)
    id: str = Field(alias="_id")
    index: str = Field(alias="_index")
    ai: dict


class AlertListData(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[AlertItemData]


class AggregationData(BaseModel):
    buckets: list[dict]


# ---- 日志中心 ----
class LogCondition(BaseModel):
    id: Optional[str] = None
    field: str
    operator: str = "eq"
    value: Union[str, int, float, list] = ""


class LogSearchBody(BaseModel):
    conditions: list[LogCondition] = Field(default_factory=list)
    kql: Optional[str] = None
    indices: Optional[list[str]] = None
    time_range: Optional[str] = None
    time_from: Optional[str] = None
    time_to: Optional[str] = None
    page: int = 1
    page_size: int = 20
    sort_field: str = "@timestamp"
    sort_order: str = "desc"


class LogItemData(BaseModel):
    # Pydantic v2 将 _ 开头字段视为私有属性，需用 alias + populate_by_name 使其正常序列化
    model_config = ConfigDict(populate_by_name=True)
    id: str = Field(alias="_id")
    index: str = Field(alias="_index")
    source: dict = Field(alias="_source")
    highlight: Optional[dict] = None
    has_ai_analysis: bool = False
    ai_doc_id: Optional[str] = None


class LogSearchData(BaseModel):
    total: int
    items: list[LogItemData]


class FieldMappingItem(BaseModel):
    name: str
    alias: str
    type: str
    example: str
    group: str
    available: bool


class MappingData(BaseModel):
    fields: list[FieldMappingItem]


class ValidateData(BaseModel):
    valid: bool
    missing_fields: list[str]
    present_fields: list[str]


class ExportBody(LogSearchBody):
    format: str = "csv"
    fields: list[str] = Field(default_factory=list)
