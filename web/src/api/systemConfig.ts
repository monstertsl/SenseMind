import request from './request'

export interface SystemConfig {
  es_retention_days: number
  raw_log_retention_days: number
  audit_log_retention_days: number
  login_fail_limit: number
  inactive_days_limit: number
  idle_timeout_minutes: number
  allowed_login_ips: string
  updated_at: string | null
}

export function getConfig() {
  return request.get<unknown, SystemConfig>('/system-config')
}

export function updateConfig(payload: Partial<SystemConfig>) {
  return request.patch<unknown, SystemConfig>('/system-config', payload)
}

// ---- LLM 配置 ----

export interface LLMConfig {
  api_endpoint: string
  api_key: string
  model: string
  temperature: number
  max_tokens: number
  timeout: number
}

export function getLLMConfig() {
  return request.get<unknown, LLMConfig>('/llm-config')
}

export function updateLLMConfig(payload: Partial<LLMConfig>) {
  return request.put<unknown, LLMConfig>('/llm-config', payload)
}

export function testLLMConnection(payload: { api_endpoint: string; api_key: string; model: string }) {
  // 响应拦截器已拆包：code!==0 时 reject，成功时返回 data 字段
  return request.post<unknown, { status: string } | null>('/llm-config/test', payload)
}

export function listLLMModels(endpoint?: string, apiKey?: string) {
  const params: Record<string, string> = {}
  if (endpoint) params.endpoint = endpoint
  if (apiKey) params.api_key = apiKey
  return request.get<unknown, string[]>('/llm-config/models', { params })
}

