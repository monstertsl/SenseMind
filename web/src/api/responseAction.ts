import request from './request'

export type ResponseRecordStatus = 'success' | 'failed'

export interface ResponseRecordItem {
  id: number
  ip: string
  action: string
  status: ResponseRecordStatus
  device_id: number
  device_name: string
  task_id: number
  task_name: string
  error_code: string
  error_message: string
  created_at: string | null
}

export interface ResponseActionPayload {
  device_id: number
  ip: string
  /** 告警文档 ID 与索引：封堵成功后据此写 blocked=true */
  event_id?: string
  event_index?: string
}

export interface ResponseActionOutcome {
  id?: number
  ip?: string
  /** skipped = 命中白名单，未下发也未写日志 */
  status: ResponseRecordStatus | 'skipped'
  device_name?: string
  error_message?: string
  /** 告警文档的 blocked 标记是否写入成功 */
  event_blocked?: boolean
}

/** 手动处置：把 IP 下发到指定设备封堵，成败都会写一条联动日志 */
export function runResponseAction(payload: ResponseActionPayload) {
  return request.post<unknown, ResponseActionOutcome>('/response/actions', payload)
}

export type ResponseRecordAction = 'block' | 'unblock'

export interface ResponseRecordQuery {
  ip?: string
  status?: ResponseRecordStatus
  action?: ResponseRecordAction
  device_id?: number
  page?: number
  page_size?: number
}

export function listResponseRecords(params: ResponseRecordQuery) {
  return request.get<
    unknown,
    { total: number; page: number; page_size: number; items: ResponseRecordItem[] }
  >('/response/records', { params })
}

export function listResponseRecordDevices() {
  return request.get<unknown, { items: { id: number; name: string }[] }>('/response/records/devices')
}

/** 撤销一条成功的封堵：设备侧解封，并新增一条解封日志 */
export function revokeResponseRecord(id: number) {
  return request.post<unknown, ResponseActionOutcome>(`/response/records/${id}/revoke`)
}
