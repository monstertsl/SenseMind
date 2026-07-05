// 全局类型定义

export type TimeRange = 'today' | 'yesterday' | '7d' | '30d' | 'custom'

export interface CustomTimeRange {
  start: string
  end: string
}

export type RefreshInterval = 'none' | '5s' | '10s' | '30s' | '1m' | '2m'

export type RiskLevel = 'healthy' | 'low' | 'medium' | 'high' | 'critical'

export interface ApiResponse<T> {
  code: number
  message: string
  data: T
  request_id: string
}

// ---- 监测中心 ----
export interface MetricsOverview {
  risk_level: RiskLevel
  total_alerts: number
  victim_assets: number
  attacker_count: number
  ai_total: number
  ai_victim_targets: number
  ai_attacker_ips: number
  ai_avg_confidence: number
  ai_confidence_prev: number
  soc_attack_distribution: Array<{ category: string; count: number }>
  threat_verdict_distribution: {
    reliable: number
    suspicious: number
    unreliable: number
    total: number
  }
  threat_source_distribution: {
    system_alert: number
    semantic_analysis: number
    total: number
  }
}

// ---- 系统信息 ----
export interface SystemInfo {
  cpu_percent: number
  cpu_count: number
  memory_percent: number
  memory_total: number
  memory_used: number
  disk_percent: number
  disk_total: number
  disk_used: number
}

// ---- 分析中心 ----
export interface AlertAi {
  alert_timestamp: string
  source_ip: string
  source_port: number | null
  destination_ip: string
  destination_port: number | null
  soc_name: string
  alert_signature: string
  confidence: number
  attack_chain: string
  handling_suggestion: string
  payload: string
  source_alert_id: string
  threat_verdict: string
  attack_result: string
  attack_technique: string
  mitre_id: string
  protocol: string
}

export interface AlertItem {
  _id: string
  _index: string
  ai: AlertAi
}

export interface AlertListResponse {
  total: number
  page: number
  page_size: number
  items: AlertItem[]
}

export interface AlertQuery {
  time_range?: TimeRange
  time_from?: string
  time_to?: string
  custom_start?: string
  custom_end?: string
  source_ip?: string
  destination_ip?: string
  soc_name?: string
  confidence?: number
  alert_signature?: string
  source_alert_id?: string
  page: number
  page_size: number
  sort_field?: string
  sort_order?: 'asc' | 'desc'
}

export interface RelatedLog {
  _id: string
  _index: string
  _source: Record<string, any>
}

export interface AlertDetail extends AlertItem {
  related_logs: RelatedLog[]
}

export interface AggregationBucket {
  key: string
  count: number
}

// ---- 日志中心 ----
export interface LogCondition {
  id: string
  field: string
  operator: string
  value: string | number | string[]
}

export interface LogSearchRequest {
  conditions: LogCondition[]
  kql?: string
  keyword?: string
  indices?: string[]
  time_range?: string
  time_from?: string
  time_to?: string
  page: number
  page_size: number
  sort_field?: string
  sort_order?: 'asc' | 'desc'
}

export interface LogItem {
  _id: string
  _index: string
  _source: Record<string, any>
  highlight?: Record<string, string[]>
  has_ai_analysis: boolean
  ai_doc_id?: string
}

export interface LogSearchResponse {
  total: number
  items: LogItem[]
}

export interface LogFieldMapping {
  name: string
  alias: string
  type: string
  example: string
  group: string
  available: boolean
}

export interface ValidateResult {
  valid: boolean
  missing_fields: string[]
  present_fields: string[]
}
