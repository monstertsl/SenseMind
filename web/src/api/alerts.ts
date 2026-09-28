import request from './request'
import type { AlertQuery, AlertListResponse, AlertDetail, AggregationBucket, TimeRange } from '@/types'

export function getAlerts(params: AlertQuery): Promise<AlertListResponse> {
  return request.get('/alerts', { params })
}

export function getAlertDetail(id: string): Promise<AlertDetail> {
  return request.get(`/alerts/${id}`)
}

export interface RuleContents {
  sid: number
  contents: string[]
  nocase: boolean
}

// 命中片段来自规则 content 字面量（Suricata 不记录命中偏移）
export function getRuleContents(sid: number): Promise<RuleContents> {
  return request.get('/alerts/rule-contents', { params: { sid } })
}

export function getAlertAggregations(
  field: string,
  timeRange: TimeRange,
  timeFrom?: string,
  timeTo?: string,
): Promise<{ buckets: AggregationBucket[] }> {
  return request.get('/alerts/aggregations', {
    params: { field, time_range: timeRange, time_from: timeFrom, time_to: timeTo },
  })
}
