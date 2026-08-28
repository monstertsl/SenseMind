import request from './request'
import type { MetricsOverview, SystemInfo, SystemMetrics, TimeRange, MetricRange } from '@/types'

export function getMetricsOverview(timeRange: TimeRange): Promise<MetricsOverview> {
  return request.get('/metrics/overview', { params: { time_range: timeRange } })
}

export function getSystemInfo(): Promise<SystemInfo> {
  return request.get('/system/info')
}

export function getSystemMetrics(range: MetricRange): Promise<SystemMetrics> {
  return request.get('/system/metrics', { params: { range } })
}

export function getClientIp(): Promise<{ ip: string }> {
  return request.get('/system/client-ip')
}
