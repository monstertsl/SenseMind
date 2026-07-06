<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { WarningFilled, User, ArrowDown, Monitor, Aim, Document, Setting } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import { useAuthStore } from '@/stores/auth'
import { getConfig } from '@/api/systemConfig'
import { changePassword } from '@/api/user'
import type { TimeRange, RefreshInterval } from '@/types'

const route = useRoute()
const router = useRouter()
const globalStore = useGlobalFilterStore()
const authStore = useAuthStore()

const baseMenus = [
  { path: '/monitor/dashboard', title: '监测中心', icon: Monitor },
  { path: '/analysis/alerts', title: '分析中心', icon: Aim },
  { path: '/log/explorer', title: '日志中心', icon: Document },
]

const adminMenus = [
  { path: '/system/settings', title: '系统设置', icon: Setting },
]

const menus = computed(() => {
  return authStore.isAdmin ? [...baseMenus, ...adminMenus] : baseMenus
})

const timeRangeOptions: { label: string; value: TimeRange }[] = [
  { label: '今天', value: 'today' },
  { label: '昨天', value: 'yesterday' },
  { label: '近7天', value: '7d' },
  { label: '近30天', value: '30d' },
  { label: '自定义', value: 'custom' },
]

const refreshIntervalOptions: { label: string; value: RefreshInterval }[] = [
  { label: '不刷新', value: 'none' },
  { label: '5秒', value: '5s' },
  { label: '10秒', value: '10s' },
  { label: '30秒', value: '30s' },
  { label: '1分钟', value: '1m' },
  { label: '2分钟', value: '2m' },
]

const activeMenu = computed(() => route.path)

const customTimeVisible = computed(() => globalStore.timeRange === 'custom')
const customRange = ref<[Date, Date] | null>(
  globalStore.customTime.start && globalStore.customTime.end
    ? [new Date(globalStore.customTime.start), new Date(globalStore.customTime.end)]
    : null,
)

function handleMenuSelect(path: string) {
  router.push(path)
}

function handleTimeRangeChange(val: TimeRange) {
  globalStore.setTimeRange(val)
}

function handleRefreshIntervalChange(val: RefreshInterval) {
  globalStore.setRefreshInterval(val)
}

function handleCustomConfirm(val: [Date, Date] | null) {
  if (val && val.length === 2) {
    globalStore.setCustomTime(
      val[0].toISOString(),
      val[1].toISOString(),
    )
  }
}

// ---- 用户下拉 ----
async function handleLogout() {
  await authStore.logout()
  router.push('/login')
}

// ---- 修改密码 ----
const pwdDialogVisible = ref(false)
const pwdForm = ref({ old_password: '', new_password: '', confirm_password: '' })
const pwdSaving = ref(false)

function openPwdDialog() {
  pwdForm.value = { old_password: '', new_password: '', confirm_password: '' }
  pwdDialogVisible.value = true
}

async function handleChangePassword() {
  if (!authStore.user) return
  if (pwdForm.value.new_password.length < 8) {
    ElMessage.warning('新密码至少 8 位')
    return
  }
  if (pwdForm.value.new_password !== pwdForm.value.confirm_password) {
    ElMessage.warning('两次输入的新密码不一致')
    return
  }
  pwdSaving.value = true
  try {
    await changePassword(authStore.user.id, {
      old_password: pwdForm.value.old_password,
      new_password: pwdForm.value.new_password,
    })
    ElMessage.success('密码已修改')
    pwdDialogVisible.value = false
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '修改失败')
  } finally {
    pwdSaving.value = false
  }
}

// ---- 静止检测 ----
const idleTimeoutMinutes = ref(30)
let idleTimer: ReturnType<typeof setTimeout> | null = null

function resetIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer)
  if (idleTimeoutMinutes.value <= 0) return
  idleTimer = setTimeout(async () => {
    ElMessage.warning('长时间无操作，已自动退出登录')
    await authStore.logout()
    router.push('/login')
  }, idleTimeoutMinutes.value * 60 * 1000)
}

async function loadIdleTimeout() {
  try {
    const cfg = await getConfig()
    idleTimeoutMinutes.value = cfg.idle_timeout_minutes || 30
  } catch {
    // 非 admin 或加载失败时用默认值
    idleTimeoutMinutes.value = 30
  }
  resetIdleTimer()
}

const idleEvents = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart']

onMounted(() => {
  idleEvents.forEach((evt) => window.addEventListener(evt, resetIdleTimer, { passive: true }))
  loadIdleTimeout()
})

onUnmounted(() => {
  idleEvents.forEach((evt) => window.removeEventListener(evt, resetIdleTimer))
  if (idleTimer) clearTimeout(idleTimer)
})
</script>

<template>
  <div class="layout">
    <!-- 顶部导航栏 -->
    <header class="topbar">
      <div class="topbar-left">
        <div class="logo">
          <img src="/logo.svg" alt="SenseMind" class="logo-img" />
          <span class="logo-text">SenseMind</span>
        </div>
        <span class="nav-divider"></span>
        <nav class="nav-menu">
          <button
            v-for="m in menus"
            :key="m.path"
            class="nav-item"
            :class="{ active: activeMenu === m.path }"
            :title="m.title"
            @click="handleMenuSelect(m.path)"
          >
            <el-icon class="nav-icon"><component :is="m.icon" /></el-icon>
            <span class="nav-label">{{ m.title }}</span>
          </button>
        </nav>
      </div>

      <div class="topbar-right">
        <el-tag
          v-if="globalStore.mappingValid === false"
          type="warning"
          size="small"
          class="mapping-warn"
        >
          <el-icon><WarningFilled /></el-icon>
          字段映射缺失 {{ globalStore.missingFields.length }} 项
        </el-tag>
        <span class="time-label">刷新间隔</span>
        <el-select
          :model-value="globalStore.refreshInterval"
          size="small"
          class="refresh-select"
          @change="handleRefreshIntervalChange"
        >
          <el-option
            v-for="opt in refreshIntervalOptions"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
        <span class="time-label">时间范围</span>
        <el-select
          :model-value="globalStore.timeRange"
          size="small"
          class="time-select"
          @change="handleTimeRangeChange"
        >
          <el-option
            v-for="opt in timeRangeOptions"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
        <el-date-picker
          v-if="customTimeVisible"
          v-model="customRange"
          type="datetimerange"
          size="small"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          format="YYYY-MM-DD HH:mm:ss"
          @change="handleCustomConfirm"
        />
        <span class="nav-divider"></span>
        <el-dropdown trigger="click" @command="(cmd: string) => cmd === 'logout' ? handleLogout() : openPwdDialog()">
          <span class="user-trigger">
            <el-icon><User /></el-icon>
            <span class="username">{{ authStore.user?.username || '用户' }}</span>
            <el-icon class="arrow"><ArrowDown /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="password">修改密码</el-dropdown-item>
              <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </header>

    <!-- 内容区 -->
    <main class="layout-content">
      <router-view v-slot="{ Component }">
        <transition name="fade" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </main>

    <!-- 修改密码弹窗 -->
    <el-dialog v-model="pwdDialogVisible" title="修改密码" width="420px">
      <el-form label-width="90px">
        <el-form-item label="原密码">
          <el-input v-model="pwdForm.old_password" type="password" show-password />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="pwdForm.new_password" type="password" show-password placeholder="至少 8 位" />
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input v-model="pwdForm.confirm_password" type="password" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwdDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="pwdSaving" @click="handleChangePassword">确认</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped lang="scss">
.layout {
  display: flex;
  flex-direction: column;
  height: 100%;
  width: 100%;
}

.topbar {
  height: 56px;
  background: $color-nav-bg;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  flex-shrink: 0;
  border-bottom: 1px solid $color-nav-border;
}

.topbar-left {
  display: flex;
  align-items: center;
  gap: 16px;
  height: 100%;
}

.logo {
  display: flex;
  align-items: center;
  gap: 8px;
  .logo-img {
    height: 28px;
    width: auto;
  }
  .logo-text {
    font-family: $font-mono;
    font-size: 16px;
    font-weight: 700;
    color: $color-nav-text-active;
    letter-spacing: 0.5px;
  }
}

.nav-divider {
  width: 2px;
  height: 20px;
  background: $color-nav-border;
  border-radius: 1px;
}

.nav-menu {
  display: flex;
  align-items: center;
  height: 100%;
}

.nav-item {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 20px;
  height: 100%;
  border: none;
  background: transparent;
  color: $color-nav-text;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  transition: color 0.2s ease;

  .nav-icon {
    display: none;
    font-size: 18px;
  }

  &:hover {
    color: $color-nav-text-active;
  }

  &.active {
    color: $color-nav-text-active;
    font-weight: 600;
  }
}

// 窄屏：菜单文字切换为图标，避免文字竖排
@media (max-width: 1100px) {
  .nav-item {
    padding: 0 14px;
    .nav-icon {
      display: inline-flex;
    }
    .nav-label {
      display: none;
    }
  }
  // 刷新间隔/时间范围：窄屏隐藏标题文字，只保留 select
  .topbar-right .time-label {
    display: none;
  }
}

.topbar-right {
  display: flex;
  align-items: center;
  gap: 12px;

  .mapping-warn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  .time-label {
    font-size: 13px;
    font-weight: 700;
    color: $color-nav-text-active;
  }

  .time-select {
    width: 120px;
    :deep(.el-input__wrapper) {
      background: rgba(255, 255, 255, 0.08);
      box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.15) inset;
    }
    :deep(.el-input__inner) {
      color: $color-nav-text-active;
    }
    :deep(.el-select__caret) {
      color: $color-nav-text;
    }
  }

  .refresh-select {
    width: 110px;
    :deep(.el-input__wrapper) {
      background: rgba(255, 255, 255, 0.08);
      box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.15) inset;
    }
    :deep(.el-input__inner) {
      color: $color-nav-text-active;
    }
    :deep(.el-select__caret) {
      color: $color-nav-text;
    }
  }

  .user-trigger {
    display: flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    color: $color-nav-text-active;
    font-size: 13px;
    outline: none;

    .username {
      max-width: 100px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .arrow {
      font-size: 12px;
    }
  }
}

.layout-content {
  flex: 1;
  overflow: auto;
  padding: 20px 24px;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.15s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
