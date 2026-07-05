import request from './request'
import type { MetricsOverview, SystemInfo, TimeRange } from '@/types'

export function getMetricsOverview(timeRange: TimeRange): Promise<MetricsOverview> {
  return request.get('/metrics/overview', { params: { time_range: timeRange } })
}

export function getSystemInfo(): Promise<SystemInfo> {
  return request.get('/system/info')
}

export function getClientIp(): Promise<{ ip: string }> {
  return request.get('/system/client-ip')
}
