import request from './request'

export interface BypassRuleItem {
  id: number
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  host: string
  remark: string
  created_at: string | null
  updated_at: string | null
}

export interface BypassRuleParams {
  keyword?: string
  page?: number
  page_size?: number
}

export function listBypassRules(params: BypassRuleParams = {}) {
  return request.get<unknown, { total: number; page: number; page_size: number; items: BypassRuleItem[] }>('/ai-bypass-rules', { params })
}

export function createBypassRule(payload: Partial<BypassRuleItem>) {
  return request.post<unknown, BypassRuleItem>('/ai-bypass-rules', payload)
}

export function updateBypassRule(id: number, payload: Partial<BypassRuleItem>) {
  return request.patch<unknown, BypassRuleItem>(`/ai-bypass-rules/${id}`, payload)
}

export function deleteBypassRule(id: number) {
  return request.delete<unknown, { message: string }>(`/ai-bypass-rules/${id}`)
}
