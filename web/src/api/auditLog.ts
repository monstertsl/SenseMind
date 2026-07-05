import request from './request'

export interface LoginLogItem {
  id: number
  username: string
  success: boolean
  ip_address: string
  user_agent: string
  message: string
  created_at: string
}

export interface SystemLogItem {
  id: number
  action: string
  target_type: string
  target_id: string
  detail: string
  operator: string
  ip_address: string
  created_at: string
}

export interface LogListResult<T> {
  total: number
  page: number
  page_size: number
  items: T[]
}

export interface LoginLogParams {
  username?: string
  success?: boolean | string
  ip_address?: string
  start_date?: string
  end_date?: string
  page?: number
  page_size?: number
}

export interface SystemLogParams {
  action?: string
  target_type?: string
  operator?: string
  start_date?: string
  end_date?: string
  page?: number
  page_size?: number
}

export function listLoginLogs(params: LoginLogParams = {}) {
  return request.get<unknown, LogListResult<LoginLogItem>>('/audit-logs/login', { params })
}

export function listSystemLogs(params: SystemLogParams = {}) {
  return request.get<unknown, LogListResult<SystemLogItem>>('/audit-logs/system', { params })
}

export function cleanupLogs(type: 'login' | 'system', days: number) {
  return request.post<unknown, { deleted_count: number; message: string }>('/audit-logs/cleanup', { type, days })
}
