import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  { path: '/', redirect: '/monitor/dashboard' },
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/pages/Login.vue'),
    meta: { title: '登录', guest: true },
  },
  {
    path: '/monitor/dashboard',
    name: 'MonitorDashboard',
    component: () => import('@/pages/MonitorDashboard.vue'),
    meta: { title: '监测中心', icon: 'Monitor', requiresAuth: true },
  },
  {
    path: '/analysis/alerts',
    name: 'AnalysisAlerts',
    component: () => import('@/pages/AnalysisAlerts.vue'),
    meta: { title: '分析中心', icon: 'View', requiresAuth: true },
  },
  {
    path: '/log/explorer',
    name: 'LogExplorer',
    component: () => import('@/pages/LogExplorer.vue'),
    meta: { title: '日志中心', icon: 'Document', requiresAuth: true },
  },
  {
    path: '/system/users',
    redirect: '/system/settings',
  },
  {
    path: '/system/settings',
    name: 'SystemSettings',
    component: () => import('@/pages/SystemSettings.vue'),
    meta: { title: '系统设置', requiresAuth: true, admin: true },
  },
  { path: '/:pathMatch(.*)*', redirect: '/monitor/dashboard' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  const token = sessionStorage.getItem('sm_token')
  const userRaw = sessionStorage.getItem('sm_user')
  const isAuthenticated = !!token
  const isAdmin = (() => {
    if (!userRaw) return false
    try {
      return JSON.parse(userRaw).role === 'admin'
    } catch {
      return false
    }
  })()

  // 已登录访问登录页 → 跳首页
  if (to.meta.guest && isAuthenticated) {
    return { path: '/monitor/dashboard' }
  }

  // 未登录访问受保护路由 → 跳登录页
  if (to.meta.requiresAuth && !isAuthenticated) {
    return { path: '/login' }
  }

  // 非 admin 访问 admin 路由 → 跳首页
  if (to.meta.admin && !isAdmin) {
    return { path: '/monitor/dashboard' }
  }
})

export default router
