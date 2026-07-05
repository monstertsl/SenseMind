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
