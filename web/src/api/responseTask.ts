import request from './request'

export interface ResponseTaskItem {
  id: number
  name: string
  device_id: number
  device_name: string
  preset_id: number
  enabled: boolean
  created_at: string | null
  updated_at: string | null
}

export interface ResponseTaskPayload {
  name: string
  device_id: number
  preset_id: number
  enabled?: boolean
}

export function listResponseTasks() {
  return request.get<unknown, { total: number; items: ResponseTaskItem[] }>('/response/tasks')
}

export function createResponseTask(payload: ResponseTaskPayload) {
  return request.post<unknown, ResponseTaskItem>('/response/tasks', payload)
}

export function updateResponseTask(id: number, payload: Partial<ResponseTaskPayload>) {
  return request.put<unknown, ResponseTaskItem>(`/response/tasks/${id}`, payload)
}

export function deleteResponseTask(id: number) {
  return request.delete<unknown, { id: number }>(`/response/tasks/${id}`)
}
