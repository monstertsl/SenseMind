import request from './request'
import type { AlertQuery, AlertSearchPreset } from '@/types'

export interface AlertPresetPayload {
  name: string
  remark?: string
  filters: Partial<AlertQuery>
}

export function listAlertPresets(keyword?: string) {
  return request.get<unknown, { total: number; items: AlertSearchPreset[] }>(
    '/alert-search-presets',
    { params: keyword ? { keyword } : {} },
  )
}

export function createAlertPreset(payload: AlertPresetPayload) {
  return request.post<unknown, AlertSearchPreset>('/alert-search-presets', payload)
}

export function updateAlertPreset(id: number, payload: Partial<AlertPresetPayload>) {
  return request.patch<unknown, AlertSearchPreset>(`/alert-search-presets/${id}`, payload)
}

export function deleteAlertPreset(id: number) {
  return request.delete<unknown, { message: string }>(`/alert-search-presets/${id}`)
}
