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

export function triggerAiAnalysis(docId: string): Promise<{ status: string; analysis: Record<string, any> }> {
  // AI 研判需执行多阶段 LLM 链，单次可能耗时数分钟，超时须与 nginx 侧（600s）匹配
  return request.post(`/analyze/${encodeURIComponent(docId)}`, {}, { timeout: 600000 })
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
