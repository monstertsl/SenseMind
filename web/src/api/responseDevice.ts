import request from './request'

export type ConfigFieldType = 'text' | 'password' | 'url' | 'int' | 'bool' | 'select' | 'textarea'

export interface ConfigField {
  name: string
  label: string
  type: ConfigFieldType
  required?: boolean
  default?: string | number | boolean
  placeholder?: string
  help?: string
  secret?: boolean
  choices?: string[]
  depends_on?: Record<string, string> | null
}

export interface DriverCapabilities {
  test: boolean
  list_blocked: boolean
  ipv6: boolean
}

export interface DriverManifest {
  key: string
  display_name: string
  schema_version: number
  config_schema: ConfigField[]
  secret_fields: string[]
  capabilities: DriverCapabilities
}

export interface ResponseDeviceItem {
  id: number
  name: string
  driver: string
  display_name: string
  schema_version: number
  enabled: boolean
  config: Record<string, unknown>
  secret_configured: Record<string, boolean>
  created_at: string | null
  updated_at: string | null
}

export interface DeviceTestResult {
  ok: boolean
  message: string
  code?: string
  retryable?: boolean
}

export interface DevicePayload {
  name: string
  driver: string
  config: Record<string, unknown>
  enabled?: boolean
}

export function listResponseDrivers() {
  return request.get<unknown, { items: DriverManifest[] }>('/response/drivers')
}

export function listResponseDevices() {
  return request.get<unknown, { total: number; items: ResponseDeviceItem[] }>('/response/devices')
}

export function createResponseDevice(payload: DevicePayload) {
  return request.post<unknown, ResponseDeviceItem>('/response/devices', payload)
}

export function updateResponseDevice(
  id: number,
  payload: { name?: string; config?: Record<string, unknown>; enabled?: boolean },
) {
  return request.put<unknown, ResponseDeviceItem>(`/response/devices/${id}`, payload)
}

export function deleteResponseDevice(id: number) {
  return request.delete<unknown, { id: number }>(`/response/devices/${id}`)
}

export function testResponseDeviceConfig(payload: { driver: string; config: Record<string, unknown> }) {
  return request.post<unknown, DeviceTestResult>('/response/devices/test', payload)
}

export function testSavedResponseDevice(id: number) {
  return request.post<unknown, DeviceTestResult>(`/response/devices/${id}/test`)
}
