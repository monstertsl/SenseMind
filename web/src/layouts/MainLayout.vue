<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { WarningFilled, User, ArrowDown } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import { useAuthStore } from '@/stores/auth'
import { getConfig, getLLMConfig } from '@/api/systemConfig'
import { changePassword } from '@/api/user'
import type { TimeRange, RefreshInterval } from '@/types'

const route = useRoute()
const router = useRouter()
const globalStore = useGlobalFilterStore()
const authStore = useAuthStore()
const llmConfigMissing = ref(false)

// 图标用字符串名：main.ts 已全局注册全部 Element Plus 图标，
// 因此换图标只需改这里，不用再加 import
interface NavMenu {
  path: string
  title: string
  icon: string
}

const baseMenus: NavMenu[] = [
  { path: '/monitor/dashboard', title: '监测中心', icon: 'Grid' },
  { path: '/analysis/alerts', title: '分析中心', icon: 'Postcard' },
  { path: '/log/explorer', title: '日志中心', icon: 'Document' },
]

// 缓存页面（组件 name）：切回时复用已有数据与筛选状态，不重新请求
const keepAlivePages = ['AnalysisAlerts']

const adminMenus: NavMenu[] = [
  { path: '/outbound', title: '联动外发', icon: 'Operation' },
  { path: '/system/settings', title: '系统设置', icon: 'SetUp' },
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

// 竖屏/窄屏折叠：<=1024px 把刷新间隔、时间范围、账号收进下拉面板，避免顶部溢出
const NARROW_BREAKPOINT = 1024
const isNarrow = ref(window.innerWidth <= NARROW_BREAKPOINT)
const narrowPanelVisible = ref(false)

function updateNarrow() {
  isNarrow.value = window.innerWidth <= NARROW_BREAKPOINT
  if (!isNarrow.value) narrowPanelVisible.value = false
}

onMounted(() => window.addEventListener('resize', updateNarrow))
onUnmounted(() => window.removeEventListener('resize', updateNarrow))

const customTimeVisible = computed(() => globalStore.timeRange === 'custom')
const customRange = ref<[Date, Date] | null>(
  globalStore.customTime.start && globalStore.customTime.end
    ? [new Date(globalStore.customTime.start), new Date(globalStore.customTime.end)]
    : null,
)

function handleMenuSelect(path: string) {
  router.push(path)
}

function isMenuActive(menu: NavMenu) {
  return activeMenu.value === menu.path || activeMenu.value.startsWith(`${menu.path}/`)
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

async function loadLLMConfig() {
  if (!authStore.isAdmin) return
  try {
    const config = await getLLMConfig()
    llmConfigMissing.value = !config.model?.trim()
  } catch {
    llmConfigMissing.value = false
  }
}

function handleLLMConfigUpdated() {
  loadLLMConfig()
}

const idleEvents = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart']

onMounted(() => {
  idleEvents.forEach((evt) => window.addEventListener(evt, resetIdleTimer, { passive: true }))
  window.addEventListener('llm-config-updated', handleLLMConfigUpdated)
  loadIdleTimeout()
  loadLLMConfig()
})

onUnmounted(() => {
  idleEvents.forEach((evt) => window.removeEventListener(evt, resetIdleTimer))
  window.removeEventListener('llm-config-updated', handleLLMConfigUpdated)
  if (idleTimer) clearTimeout(idleTimer)
})
</script>

<template>
  <div class="layout">
    <!-- 顶部导航栏 -->
    <header class="topbar">
      <div class="topbar-left">
        <a
          class="logo"
          href="https://github.com/monstertsl/SenseMind"
          target="_blank"
          rel="noopener noreferrer"
          aria-label="SenseMind GitHub 仓库"
        >
          <img src="/logo.svg" alt="SenseMind" class="logo-img" />
          <span class="logo-text">SenseMind</span>
        </a>
        <span class="nav-divider"></span>
        <nav class="nav-menu">
          <button
            v-for="m in menus"
            :key="m.path"
            type="button"
            class="nav-item"
            :class="{ active: isMenuActive(m) }"
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
          <span class="warn-text">字段映射缺失 {{ globalStore.missingFields.length }} 项</span>
        </el-tag>
        <el-tag
          v-if="authStore.isAdmin && llmConfigMissing"
          type="warning"
          size="small"
          class="mapping-warn llm-warn"
          role="button"
          tabindex="0"
          @click="router.push({ path: '/system/settings', query: { llm: 'configure' } })"
          @keydown.enter="router.push({ path: '/system/settings', query: { llm: 'configure' } })"
        >
          <el-icon><WarningFilled /></el-icon>
          <span class="warn-text">LLM 模型未配置</span>
        </el-tag>
        <template v-if="!isNarrow">
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
        </template>

        <!-- 竖屏/窄屏：刷新间隔、时间范围与账号折叠进下拉面板，避免顶部溢出 -->
        <el-popover
          v-else
          v-model:visible="narrowPanelVisible"
          placement="bottom-end"
          :width="268"
          trigger="click"
        >
          <template #reference>
            <button class="narrow-trigger" type="button" title="筛选与账号">
              <el-icon><ArrowDown /></el-icon>
            </button>
          </template>
          <div class="narrow-panel">
            <div class="narrow-field">
              <span class="narrow-label">刷新间隔</span>
              <el-select
                :model-value="globalStore.refreshInterval"
                size="small"
                :teleported="false"
                @change="handleRefreshIntervalChange"
              >
                <el-option
                  v-for="opt in refreshIntervalOptions"
                  :key="opt.value"
                  :label="opt.label"
                  :value="opt.value"
                />
              </el-select>
            </div>
            <div class="narrow-field">
              <span class="narrow-label">时间范围</span>
              <el-select
                :model-value="globalStore.timeRange"
                size="small"
                :teleported="false"
                @change="handleTimeRangeChange"
              >
                <el-option
                  v-for="opt in timeRangeOptions"
                  :key="opt.value"
                  :label="opt.label"
                  :value="opt.value"
                />
              </el-select>
            </div>
            <div v-if="customTimeVisible" class="narrow-field narrow-field-column">
              <span class="narrow-label">自定义时间</span>
              <el-date-picker
                v-model="customRange"
                type="datetimerange"
                size="small"
                :teleported="false"
                range-separator="至"
                start-placeholder="开始时间"
                end-placeholder="结束时间"
                format="YYYY-MM-DD HH:mm:ss"
                @change="handleCustomConfirm"
              />
            </div>
            <el-divider class="narrow-divider" />
            <div class="narrow-account">
              <span class="narrow-user">
                <el-icon><User /></el-icon>
                {{ authStore.user?.username || '用户' }}
              </span>
              <div class="narrow-actions">
                <el-button size="small" @click="openPwdDialog">修改密码</el-button>
                <el-button size="small" type="danger" plain @click="handleLogout">退出登录</el-button>
              </div>
            </div>
          </div>
        </el-popover>
      </div>
    </header>

    <!-- 内容区 -->
    <main class="layout-content">
      <router-view v-slot="{ Component }">
        <transition name="fade" mode="out-in">
          <keep-alive :include="keepAlivePages">
            <component :is="Component" />
          </keep-alive>
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
  color: inherit;
  text-decoration: none;
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
  font-family: inherit;
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
  .logo-text {
    display: none;
  }
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
    cursor: pointer;
    font-family: $font-mono;
    font-feature-settings: 'tnum';
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
      font-family: $font-mono;
    }

    .arrow {
      font-size: 12px;
    }
  }
}

.narrow-trigger {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  padding: 0;
  border: 1px solid rgba(255, 255, 255, 0.22);
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.08);
  color: $color-nav-text-active;
  cursor: pointer;

  &:hover {
    background: rgba(255, 255, 255, 0.18);
  }
}

.narrow-panel {
  display: flex;
  flex-direction: column;
  gap: 10px;

  .narrow-field {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;

    :deep(.el-select) {
      width: 140px;
    }
  }

  .narrow-field-column {
    flex-direction: column;
    align-items: stretch;

    :deep(.el-date-editor) {
      width: 100%;
    }
  }

  .narrow-label {
    color: $color-text-secondary;
    font-size: 13px;
  }

  .narrow-divider {
    margin: 2px 0;
  }

  .narrow-account {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .narrow-user {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: $color-text-primary;
    font-family: $font-mono;
    font-size: 13px;
  }

  .narrow-actions {
    display: flex;
    gap: 8px;
  }
}

@media (max-width: 1024px) {
  .topbar {
    padding: 0 16px;
    gap: 10px;
    overflow: hidden;
  }

  .topbar-right {
    gap: 10px;
    min-width: 0;
    flex-wrap: nowrap;
  }

  .nav-item {
    min-width: 44px;
    padding: 0 14px;
  }

  .narrow-trigger {
    width: 34px;
    height: 34px;
  }
}

@media (max-width: 640px) {
  .topbar {
    padding: 0 10px;
  }

  .nav-item {
    min-width: 40px;
    padding: 0 10px;
  }

  // 极窄屏告警标签只留图标，避免挤出边界
  .topbar-right .warn-text {
    display: none;
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
