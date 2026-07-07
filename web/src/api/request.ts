import axios, { type AxiosInstance, type AxiosResponse } from 'axios'
import type { ApiResponse } from '@/types'

const TOKEN_KEY = 'sm_token'
const LOGIN_PATH = '/login'

const request: AxiosInstance = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// 请求拦截：注入 Authorization 头
request.interceptors.request.use(
  (config) => {
    const token = sessionStorage.getItem(TOKEN_KEY)
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error),
)

// 响应拦截：滑动续期 + 401 跳登录 + ApiResponse 拆包
request.interceptors.response.use(
  (response: AxiosResponse<ApiResponse<unknown>>) => {
    // 滑动续期：后端在剩余<10min 时通过 X-Refreshed-Token 下发新 token
    const refreshed = response.headers['x-refreshed-token']
    if (refreshed) {
      sessionStorage.setItem(TOKEN_KEY, refreshed)
    }
    const res = response.data
    if (res.code !== 0) {
      return Promise.reject(new Error(res.message || 'Error'))
    }
    return res.data as any
  },
  (error) => {
    // 401：清凭据 + 跳登录页（用 window.location 避免在拦截器内触发路由守卫循环）
    const status = error?.response?.status
    const url = error?.config?.url || ''
    const isLogoutRequest = url.includes('/auth/logout')
    const isLoginRequest = url.includes('/auth/login')
    if (status === 401) {
      // 登录请求的 401（用户名/密码错误）：正常 reject，由登录页显示错误提示
      if (isLoginRequest) {
        return Promise.reject(error)
      }
      // logout 请求的 401 由 auth store 静默处理，不触发拦截器跳转
      if (!isLogoutRequest) {
        sessionStorage.removeItem(TOKEN_KEY)
        sessionStorage.removeItem('sm_user')
        if (window.location.pathname !== LOGIN_PATH) {
          window.location.href = LOGIN_PATH
        }
      }
      // 返回 pending promise，避免调用方 catch 到错误并弹出 ElMessage
      // 页面即将跳转或已清除凭据，pending 的请求无需处理结果
      return new Promise(() => {})
    }
    // 静默失败：不弹出 ElMessage，由调用方决定是否自动重试
    return Promise.reject(error)
  },
)

export default request
