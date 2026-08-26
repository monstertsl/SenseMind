import request from './request'
import type { AlertQuery, AlertListResponse, AlertDetail, AggregationBucket, TimeRange } from '@/types'

export function getAlerts(params: AlertQuery): Promise<AlertListResponse> {
  return request.get('/alerts', { params })
}

export function getAlertDetail(id: string): Promise<AlertDetail> {
  return request.get(`/alerts/${id}`)
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
