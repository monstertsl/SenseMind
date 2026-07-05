import request from './request'
import type {
  LogSearchRequest,
  LogSearchResponse,
  LogFieldMapping,
  ValidateResult,
} from '@/types'

export function searchLogs(params: LogSearchRequest): Promise<LogSearchResponse> {
  return request.post('/logs/search', params)
}

export function getLogDetail(id: string, index: string): Promise<Record<string, any>> {
  return request.get(`/logs/${encodeURIComponent(id)}`, { params: { index } })
}

export function getLogMapping(indices?: string[]): Promise<{ fields: LogFieldMapping[] }> {
  return request.get('/logs/mapping', { params: { indices: indices?.join(',') } })
}

export function validateMapping(): Promise<ValidateResult> {
  return request.get('/system/validate-mapping')
}

export function exportLogs(
  params: LogSearchRequest & { format: 'csv' | 'json'; fields: string[] },
): Promise<{ task_id: string }> {
  return request.post('/logs/export', params)
}
