import request from './request'

export type MailWatchPeriod = 'realtime' | '30m' | '2h' | '4h' | 'daily'

export interface AlertMailWatch {
  id: number
  preset_id: number
  preset_name: string
  period: MailWatchPeriod
  daily_hour: number | null
  recipients: string[]
  next_run_at: string
}

export interface AlertMailWatchPayload {
  preset_id: number
  period: MailWatchPeriod
  daily_hour?: number | null
  recipients: string[]
}

export function listAlertMailWatches() {
  return request.get<unknown, AlertMailWatch[]>('/alert-mail-watches')
}

export function createAlertMailWatch(payload: AlertMailWatchPayload) {
  return request.post<unknown, AlertMailWatch>('/alert-mail-watches', payload)
}

export function updateAlertMailWatch(id: number, payload: AlertMailWatchPayload) {
  return request.put<unknown, AlertMailWatch>(`/alert-mail-watches/${id}`, payload)
}

export function deleteAlertMailWatch(id: number) {
  return request.delete<unknown, { message: string }>(`/alert-mail-watches/${id}`)
}
