import request from './request'

export interface WhitelistItem {
  id: number
  value: string
  note: string
  created_at: string | null
}

export function listResponseWhitelist() {
  return request.get<unknown, { total: number; items: WhitelistItem[] }>('/response/whitelist')
}

export function createResponseWhitelist(payload: { value: string; note?: string }) {
  return request.post<unknown, { id: number; value: string; note: string }>('/response/whitelist', payload)
}

export function deleteResponseWhitelist(id: number) {
  return request.delete<unknown, { id: number }>(`/response/whitelist/${id}`)
}
