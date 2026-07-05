import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { getMe, logout as apiLogout } from '@/api/auth'

const TOKEN_KEY = 'sm_token'
const USER_KEY = 'sm_user'

export interface AuthUser {
  id: number
  username: string
  role: 'admin' | 'user'
  auth_mode: 'PASSWORD_ONLY' | 'TOTP_ONLY' | 'PASSWORD_AND_TOTP'
  is_active: boolean
  totp_enabled: boolean
  last_login_at: string | null
  created_at: string | null
}

function loadUser(): AuthUser | null {
  const raw = sessionStorage.getItem(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as AuthUser
  } catch {
    return null
  }
}

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string | null>(sessionStorage.getItem(TOKEN_KEY))
  const user = ref<AuthUser | null>(loadUser())

  const isAuthenticated = computed(() => !!token.value)
  const isAdmin = computed(() => user.value?.role === 'admin')

  function setAuth(newToken: string, newUser: AuthUser) {
    token.value = newToken
    user.value = newUser
    sessionStorage.setItem(TOKEN_KEY, newToken)
    sessionStorage.setItem(USER_KEY, JSON.stringify(newUser))
  }

  function setToken(newToken: string) {
    token.value = newToken
    sessionStorage.setItem(TOKEN_KEY, newToken)
  }

  function setUser(newUser: AuthUser) {
    user.value = newUser
    sessionStorage.setItem(USER_KEY, JSON.stringify(newUser))
  }

  function clearAuth() {
    token.value = null
    user.value = null
    sessionStorage.removeItem(TOKEN_KEY)
    sessionStorage.removeItem(USER_KEY)
  }

  async function fetchCurrentUser() {
    try {
      const me = await getMe()
      setUser(me as AuthUser)
      return me
    } catch {
      clearAuth()
      return null
    }
  }

  async function logout() {
    try {
      await apiLogout()
    } catch {
      // 忽略网络错误，仍清除本地状态
    }
    clearAuth()
  }

  return {
    token,
    user,
    isAuthenticated,
    isAdmin,
    setAuth,
    setToken,
    setUser,
    clearAuth,
    fetchCurrentUser,
    logout,
  }
})
