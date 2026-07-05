<script setup lang="ts">
import { ref, reactive, onMounted, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import { getConfig, updateConfig, type SystemConfig } from '@/api/systemConfig'
import { getClientIp } from '@/api/metrics'
import {
  listLoginLogs, listSystemLogs,
  type LoginLogItem, type SystemLogItem,
} from '@/api/auditLog'
import UserManage from '@/pages/UserManage.vue'

// ---- 集成配置 ----
const configLoading = ref(false)
const configSaving = ref(false)
const config = reactive<SystemConfig>({
  es_retention_days: 180,
  raw_log_retention_days: 7,
  audit_log_retention_days: 180,
  login_fail_limit: 5,
  inactive_days_limit: 90,
  idle_timeout_minutes: 30,
  allowed_login_ips: '',
  updated_at: null,
})

async function fetchConfig() {
  configLoading.value = true
  try {
    const data = await getConfig()
    Object.assign(config, data)
  } catch (e: any) {
    ElMessage.error(e?.message || '加载配置失败')
  } finally {
    configLoading.value = false
  }
}

// ---- 当前客户端 IP（用于白名单检测）----
const currentIp = ref('')
const ipWarning = ref('')

async function fetchCurrentIp() {
  try {
    const data = await getClientIp()
    currentIp.value = data.ip
  } catch {
    // 获取失败不阻塞页面
  }
}

function checkIpWhitelist(value: string) {
  ipWarning.value = ''
  if (!value.trim() || !currentIp.value) return
  const ips = value.split(',').map((s: string) => s.trim()).filter(Boolean)
  if (!ips.includes(currentIp.value)) {
    ipWarning.value = `当前 IP ${currentIp.value} 不在白名单中，保存后可能导致无法登录`
  }
}

watch(() => config.allowed_login_ips, (val) => checkIpWhitelist(val))

async function handleSaveConfig() {
  configSaving.value = true
  try {
    await updateConfig({
      es_retention_days: config.es_retention_days,
      raw_log_retention_days: config.raw_log_retention_days,
      audit_log_retention_days: config.audit_log_retention_days,
      login_fail_limit: config.login_fail_limit,
      inactive_days_limit: config.inactive_days_limit,
      idle_timeout_minutes: config.idle_timeout_minutes,
      allowed_login_ips: config.allowed_login_ips,
    })
    ElMessage.success('配置已保存')
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '保存失败')
  } finally {
    configSaving.value = false
  }
}

// ---- 登录日志 ----
const loginLogs = ref<LoginLogItem[]>([])
const loginTotal = ref(0)
const loginLoading = ref(false)
const loginPage = ref(1)
const loginPageSize = ref(10)
const loginFilter = reactive({
  username: '',
  success: '' as '' | 'true' | 'false',
  ip_address: '',
})

async function fetchLoginLogs() {
  loginLoading.value = true
  try {
    const params: Record<string, unknown> = {
      page: loginPage.value,
      page_size: loginPageSize.value,
    }
    if (loginFilter.username) params.username = loginFilter.username
    if (loginFilter.success) params.success = loginFilter.success === 'true'
    if (loginFilter.ip_address) params.ip_address = loginFilter.ip_address
    const data = await listLoginLogs(params as any)
    loginLogs.value = data.items
    loginTotal.value = data.total
  } catch (e: any) {
    ElMessage.error(e?.message || '加载登录日志失败')
    loginLogs.value = []
    loginTotal.value = 0
  } finally {
    loginLoading.value = false
  }
}

function handleLoginSearch() {
  loginPage.value = 1
  fetchLoginLogs()
}

function handleLoginPageChange(p: number) {
  loginPage.value = p
  fetchLoginLogs()
}

// ---- 系统日志 ----
const systemLogs = ref<SystemLogItem[]>([])
const systemTotal = ref(0)
const systemLoading = ref(false)
const systemPage = ref(1)
const systemPageSize = ref(10)
const systemFilter = reactive({
  action: '',
  operator: '',
})

const ACTION_LABELS: Record<string, string> = {
  create: '创建用户',
  update: '修改用户',
  delete: '删除用户',
  reset_password: '重置密码',
  auto_disable: '自动禁用',
  cleanup_raw_log: '清理原始日志',
  cleanup_es_log: '清理ES索引',
  cleanup_audit_log: '清理审计日志',
}

async function fetchSystemLogs() {
  systemLoading.value = true
  try {
    const params: Record<string, unknown> = {
      page: systemPage.value,
      page_size: systemPageSize.value,
    }
    if (systemFilter.action) params.action = systemFilter.action
    if (systemFilter.operator) params.operator = systemFilter.operator
    const data = await listSystemLogs(params as any)
    systemLogs.value = data.items
    systemTotal.value = data.total
  } catch (e: any) {
    ElMessage.error(e?.message || '加载系统日志失败')
    systemLogs.value = []
    systemTotal.value = 0
  } finally {
    systemLoading.value = false
  }
}

function handleSystemSearch() {
  systemPage.value = 1
  fetchSystemLogs()
}

function handleSystemPageChange(p: number) {
  systemPage.value = p
  fetchSystemLogs()
}

function formatTime(t: string | null): string {
  if (!t) return '-'
  try {
    return new Date(t).toLocaleString('zh-CN', { hour12: false })
  } catch {
    return t
  }
}

onMounted(() => {
  fetchConfig()
  fetchCurrentIp()
  fetchLoginLogs()
  fetchSystemLogs()
})
</script>

<template>
  <div class="system-settings">
    <!-- 用户管理 -->
    <div class="section-block">
      <div class="block-title">用户管理</div>
      <UserManage />
    </div>

    <!-- 集成配置 -->
    <div class="section-block">
      <div class="block-title">集成配置</div>
      <div v-loading="configLoading" class="config-row">
        <!-- 存储优化 -->
        <div class="config-section">
          <div class="section-title">存储优化</div>
          <div class="config-grid">
            <div class="config-item">
              <label>ES 日志保留天数</label>
              <el-input-number v-model="config.es_retention_days" :min="1" :max="365" />
            </div>
            <div class="config-item">
              <label>原始日志保留天数</label>
              <el-input-number v-model="config.raw_log_retention_days" :min="1" :max="90" />
            </div>
            <div class="config-item">
              <label>系统日志保留天数</label>
              <el-input-number v-model="config.audit_log_retention_days" :min="30" :max="365" />
            </div>
          </div>
        </div>

        <!-- 安全策略 -->
        <div class="config-section">
          <div class="section-title">安全策略</div>
          <div class="config-grid">
            <div class="config-item">
              <label>登录失败次数限制</label>
              <el-input-number v-model="config.login_fail_limit" :min="3" :max="20" />
            </div>
            <div class="config-item">
              <label>长期未登录禁用天数</label>
              <el-input-number v-model="config.inactive_days_limit" :min="30" :max="365" />
            </div>
            <div class="config-item">
              <label>页面静止时长（分钟）</label>
              <el-input-number v-model="config.idle_timeout_minutes" :min="1" :max="480" />
            </div>
            <div class="config-item config-item-wide">
              <label>允许登录 IP 白名单</label>
              <el-input
                v-model="config.allowed_login_ips"
                type="textarea"
                :rows="2"
                placeholder="留空=全部允许，多个 IP 用逗号分隔"
              />
              <div v-if="ipWarning" class="ip-warning">{{ ipWarning }}</div>
            </div>
          </div>
        </div>
      </div>
      <div class="config-actions">
        <el-button type="primary" :loading="configSaving" @click="handleSaveConfig">保存配置</el-button>
      </div>
    </div>

    <!-- 登录日志 + 系统日志 并排 -->
    <div class="logs-row">
      <!-- 登录日志 -->
      <div class="log-section">
        <div class="block-title">登录日志</div>
        <div class="log-pane">
          <div class="log-toolbar">
            <el-input v-model="loginFilter.username" placeholder="用户名" clearable class="filter-input" @keyup.enter="handleLoginSearch" />
            <el-select v-model="loginFilter.success" placeholder="结果" clearable class="filter-select">
              <el-option label="成功" value="true" />
              <el-option label="失败" value="false" />
            </el-select>
            <el-input v-model="loginFilter.ip_address" placeholder="IP" clearable class="filter-input" @keyup.enter="handleLoginSearch" />
            <el-button type="primary" :icon="Search" @click="handleLoginSearch">查询</el-button>
          </div>
          <el-table v-loading="loginLoading" :data="loginLogs" stripe max-height="320">
            <el-table-column prop="username" label="用户名" width="100" />
            <el-table-column label="结果" width="80">
              <template #default="{ row }">
                <el-tag :type="row.success ? 'success' : 'danger'" size="small">{{ row.success ? '成功' : '失败' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="ip_address" label="IP" width="130" />
            <el-table-column label="时间" width="160">
              <template #default="{ row }"><span class="font-mono">{{ formatTime(row.created_at) }}</span></template>
            </el-table-column>
            <el-table-column prop="message" label="消息" min-width="160" show-overflow-tooltip />
          </el-table>
          <div class="pagination">
            <el-pagination
              v-model:current-page="loginPage"
              :page-size="loginPageSize"
              :total="loginTotal"
              layout="total, prev, pager, next"
              small
              @current-change="handleLoginPageChange"
            />
          </div>
        </div>
      </div>

      <!-- 系统日志 -->
      <div class="log-section">
        <div class="block-title">系统日志</div>
        <div class="log-pane">
          <div class="log-toolbar">
            <el-select v-model="systemFilter.action" placeholder="操作类型" clearable class="filter-select-wide">
              <el-option v-for="(label, key) in ACTION_LABELS" :key="key" :label="label" :value="key" />
            </el-select>
            <el-input v-model="systemFilter.operator" placeholder="操作人" clearable class="filter-input" @keyup.enter="handleSystemSearch" />
            <el-button type="primary" :icon="Search" @click="handleSystemSearch">查询</el-button>
          </div>
          <el-table v-loading="systemLoading" :data="systemLogs" stripe max-height="320">
            <el-table-column label="操作类型" width="130">
              <template #default="{ row }">
                <el-tag size="small">{{ ACTION_LABELS[row.action] || row.action }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="operator" label="操作人" width="90" />
            <el-table-column prop="ip_address" label="IP" width="120" />
            <el-table-column label="时间" width="150">
              <template #default="{ row }"><span class="font-mono">{{ formatTime(row.created_at) }}</span></template>
            </el-table-column>
            <el-table-column prop="detail" label="详情" min-width="160" show-overflow-tooltip />
          </el-table>
          <div class="pagination">
            <el-pagination
              v-model:current-page="systemPage"
              :page-size="systemPageSize"
              :total="systemTotal"
              layout="total, prev, pager, next"
              small
              @current-change="handleSystemPageChange"
            />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
.system-settings {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

// 三个大板块统一样式：白底 + 边框 + 圆角 + 内边距
.section-block,
.log-section {
  background: #ffffff;
  border: 1px solid #e4e7ed;
  border-radius: $radius-md;
  padding: 18px 20px;
  display: flex;
  flex-direction: column;
  gap: 14px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
}

.block-title {
  font-size: 15px;
  font-weight: 700;
  color: $color-text-primary;
  padding-left: 10px;
  border-left: 4px solid $color-primary;
}

.config-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

// 子卡片（存储优化 / 安全策略）用浅灰底，与外层白底形成层次
.config-section {
  padding: 16px 18px;
  background: $color-bg-soft;
  border: 1px solid #ebeef5;
  border-radius: $radius-md;

  .section-title {
    font-size: 14px;
    font-weight: 700;
    color: $color-primary;
    margin-bottom: 14px;
    padding-left: 8px;
    border-left: 3px solid $color-primary;
  }
}

.config-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 14px 20px;
  align-items: start;
}

.config-item {
  display: flex;
  flex-direction: column;
  gap: 6px;

  label {
    font-size: 13px;
    font-weight: 500;
    color: $color-text-regular;
  }

  &.config-item-wide {
    grid-column: 1 / -1;
  }
}

.config-actions {
  display: flex;
  justify-content: flex-end;
  padding-top: 4px;
  border-top: 1px dashed #ebeef5;
}

.logs-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  align-items: stretch;
}

.log-pane {
  display: flex;
  flex-direction: column;
  gap: 10px;
  flex: 1;
}

.log-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  padding: 10px 12px;
  background: $color-bg-soft;
  border: 1px solid #ebeef5;
  border-radius: $radius-sm;

  .filter-input {
    width: 120px;
  }

  .filter-select {
    width: 90px;
  }

  .filter-select-wide {
    width: 130px;
  }
}

.pagination {
  display: flex;
  justify-content: flex-end;
  padding-top: 4px;
  margin-top: auto;
}

// 统一两个表格行高，与日志中心 LogList 行高保持一致
:deep(.el-table) {
  .el-table__cell {
    padding: 11px 0;
  }

  .el-table__header .cell {
    padding: 0 8px;
    line-height: 22px;
    font-size: 13px;
    font-weight: 700;
  }

  .el-table__body .cell {
    padding: 0 8px;
    line-height: 22px;
    font-size: 13px;
    font-family: $font-mono;
    font-feature-settings: 'tnum';
  }

  .el-table__body .el-tag {
    font-family: $font-mono;
    font-feature-settings: 'tnum';
    font-weight: 600;
  }
}

// 集成配置内容（label / input）使用等宽字体，标题和按钮保持原样
.config-item {
  label {
    font-size: 14px;
    font-weight: 600;
    font-family: $font-mono;
    font-feature-settings: 'tnum';
    color: $color-text-primary;
  }

  :deep(.el-input__inner),
  :deep(.el-textarea__inner) {
    font-size: 14px;
    font-weight: 600;
    font-family: $font-mono;
    font-feature-settings: 'tnum';
  }
}

.ip-warning {
  margin-top: 4px;
  font-size: 12px;
  font-weight: 600;
  font-family: $font-mono;
  color: #e6a23c;
}
</style>
