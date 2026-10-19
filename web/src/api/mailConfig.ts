import request from './request'

export interface MailConfig {
  protocol: 'smtp' | 'smtps'
  host: string
  port: number
  username: string
  password_configured: boolean
  use_ssl: boolean
  sender_name: string
}

export interface MailConfigUpdate {
  protocol: MailConfig['protocol']
  host: string
  port: number
  username: string
  password: string
  use_ssl: boolean
  sender_name: string
}

export function getMailConfig() {
  return request.get<unknown, MailConfig>('/mail-config')
}

export function updateMailConfig(payload: MailConfigUpdate) {
  return request.put<unknown, MailConfig>('/mail-config', payload)
}

export function sendTestMail(recipient: string, config: MailConfigUpdate) {
  return request.post<unknown, { status: string }>('/mail-config/test', { recipient, ...config })
}