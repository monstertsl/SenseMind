import request from './request'

export type AuthMode = 'PASSWORD_ONLY' | 'TOTP_ONLY' | 'PASSWORD_AND_TOTP'

export interface UserItem {
  id: number
  username: string
  role: 'admin' | 'user'
  auth_mode: AuthMode
  is_active: boolean
  totp_enabled: boolean
  failed_login_attempts: number
  last_login_at: string | null
  created_at: string | null
}

export interface CreateUserPayload {
  username: string
  password?: string
  role: 'admin' | 'user'
  auth_mode: AuthMode
  is_active?: boolean
}

export interface UpdateUserPayload {
  role?: 'admin' | 'user'
  auth_mode?: AuthMode
  is_active?: boolean
}

export interface TotpResult {
  secret: string
  uri: string
}

export function listUsers() {
  return request.get<unknown, UserItem[]>('/users')
}

export function createUser(payload: CreateUserPayload) {
  return request.post<unknown, UserItem>('/users', payload)
}

export function updateUser(id: number, payload: UpdateUserPayload) {
  return request.patch<unknown, UserItem>(`/users/${id}`, payload)
}

export function deleteUser(id: number) {
  return request.delete<unknown, { message: string }>(`/users/${id}`)
}

export function changePassword(id: number, payload: { old_password: string; new_password: string }) {
  return request.post<unknown, { message: string }>(`/users/${id}/password`, payload)
}

export function resetPassword(id: number, payload: { new_password: string }) {
  return request.put<unknown, { message: string }>(`/users/${id}/password/reset`, payload)
}

export function enableTotp(id: number) {
  return request.post<unknown, TotpResult>(`/users/${id}/totp/enable`)
}

export function disableTotp(id: number, payload: { code?: string }) {
  return request.post<unknown, { message: string }>(`/users/${id}/totp/disable`, payload)
}

export function resetTotp(id: number) {
  return request.post<unknown, TotpResult>(`/users/${id}/totp/reset`)
}

export function getTotpSecret(id: number) {
  return request.get<unknown, TotpResult>(`/users/${id}/totp/secret`)
}
