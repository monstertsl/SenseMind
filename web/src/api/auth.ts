import request from './request'

export interface CheckUserResult {
  exists: boolean
  auth_mode: 'PASSWORD_ONLY' | 'TOTP_ONLY' | 'PASSWORD_AND_TOTP'
  totp_enabled: boolean
}

export interface LoginPayload {
  username: string
  password?: string
  totp_code?: string
}

export interface LoginResult {
  access_token: string
  user: {
    id: number
    username: string
    role: 'admin' | 'user'
    auth_mode: string
    is_active: boolean
    totp_enabled: boolean
    last_login_at: string | null
    created_at: string | null
  }
}

export function checkUser(username: string) {
  return request.post<unknown, CheckUserResult>('/auth/check-user', { username })
}

export function login(payload: LoginPayload) {
  return request.post<unknown, LoginResult>('/auth/login', payload)
}

export function logout() {
  return request.post<unknown, { message: string }>('/auth/logout')
}

export function getMe() {
  return request.get<unknown, LoginResult['user']>('/auth/me')
}
