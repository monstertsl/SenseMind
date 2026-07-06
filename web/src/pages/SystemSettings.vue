<script setup lang="ts">
import { ref, reactive, onMounted, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import { getConfig, updateConfig, type SystemConfig } from '@/api/systemConfig'
import {
  getLLMConfig, updateLLMConfig, testLLMConnection, listLLMModels,
  type LLMConfig,
} from '@/api/systemConfig'
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

// ---- LLM 模型配置 ----
const llmLoading = ref(false)
const llmSaving = ref(false)
const llmTesting = ref(false)
const llmModelsLoaded = ref(false)
const llmModelOptions = ref<{ label: string; value: string }[]>([])
// 已保存的配置（用于显示模型名称）
const llmSaved = reactive<LLMConfig>({
  api_endpoint: '',
  api_key: '',
  model: '',
  temperature: 0.1,
  max_tokens: 8000,
  timeout: 60,
})
// 对话框中的编辑副本
const llmDialogVisible = ref(false)
const llmForm = reactive<LLMConfig>({
  api_endpoint: '',
  api_key: '',
  model: '',
  temperature: 0.1,
  max_tokens: 8000,
  timeout: 60,
})
// 是否使用自定义模型名称（手动输入而非从列表选择）
const useCustomModel = ref(false)

async function fetchLLMConfig() {
  llmLoading.value = true
  try {
    const data = await getLLMConfig()
    Object.assign(llmSaved, data)
  } catch {
    // 获取失败不阻塞页面
  } finally {
    llmLoading.value = false
  }
}

function openLLMDialog() {
  // 复制已保存的配置到编辑表单
  Object.assign(llmForm, llmSaved)
  useCustomModel.value = false
  llmModelsLoaded.value = false
  llmModelOptions.value = []
  llmDialogVisible.value = true
}

function handleModelChange(val: string) {
  if (val === '__custom__') {
    useCustomModel.value = true
    llmForm.model = ''
  }
}

// 每次展开下拉框时自动获取模型列表
function handleModelVisible(visible: boolean) {
  if (visible && llmForm.api_endpoint.trim()) {
    fetchLLMModels(llmForm.api_endpoint.trim(), (llmForm.api_key || '').trim())
  }
}

// 当 endpoint 或 key 变化时自动获取模型列表
watch(() => [llmForm.api_endpoint, llmForm.api_key], ([ep, key]) => {
  if (ep && ep.trim()) {
    fetchLLMModels(ep.trim(), (key || '').trim())
  } else {
    llmModelOptions.value = []
    llmModelsLoaded.value = false
  }
})

async function fetchLLMModels(endpoint: string, apiKey: string) {
  try {
    const data = await listLLMModels(endpoint, apiKey)
    llmModelOptions.value = data.map(m => ({ label: m, value: m }))
    llmModelsLoaded.value = true
  } catch {
    llmModelOptions.value = []
    llmModelsLoaded.value = false
  }
}

async function handleSaveLLM() {
  if (!llmForm.api_endpoint.trim()) {
    ElMessage.warning('API Endpoint 不能为空')
    return
  }
  if (useCustomModel.value && !llmForm.model.trim()) {
    ElMessage.warning('请输入自定义模型名称')
    return
  }
  llmSaving.value = true
  try {
    await updateLLMConfig({
      api_endpoint: llmForm.api_endpoint,
      api_key: llmForm.api_key,
      model: llmForm.model,
      temperature: llmForm.temperature,
      max_tokens: llmForm.max_tokens,
      timeout: llmForm.timeout,
    })
    Object.assign(llmSaved, llmForm)
    ElMessage.success('LLM 配置已保存并生效')
    llmDialogVisible.value = false
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '保存失败')
  } finally {
    llmSaving.value = false
  }
}

async function handleTestLLM() {
  if (!llmForm.api_endpoint.trim()) {
    ElMessage.warning('API Endpoint 不能为空')
    return
  }
  if (useCustomModel.value && !llmForm.model.trim()) {
    ElMessage.warning('请输入自定义模型名称')
    return
  }
  llmTesting.value = true
  try {
    // 响应拦截器已拆包：code!==0 会 reject，未抛异常即为成功
    await testLLMConnection({
      api_endpoint: llmForm.api_endpoint,
      api_key: llmForm.api_key,
      model: llmForm.model,
    })
    ElMessage.success('连接成功')
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '测试失败')
  } finally {
    llmTesting.value = false
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
  update_security_policy: '安全策略',
  update_storage_policy: '集成配置',
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
  fetchLLMConfig()
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
        <!-- 安全策略（左） -->
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

        <!-- 右列：存储优化 + LLM 模型 -->
        <div class="config-right-col">
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

          <!-- LLM 模型 -->
          <div v-loading="llmLoading" class="config-section config-section-llm">
            <div class="section-title">LLM 模型</div>
            <div class="llm-info">
              <span v-if="llmSaved.model" class="llm-model-name">{{ llmSaved.model }}</span>
              <span v-else class="llm-model-empty">未配置</span>
              <el-button type="primary" text @click="openLLMDialog">设置</el-button>
            </div>
          </div>
        </div>
      </div>
      <div class="config-actions">
        <el-button type="primary" :loading="configSaving" @click="handleSaveConfig">保存配置</el-button>
      </div>
    </div>

    <!-- LLM 配置对话框 -->
    <el-dialog v-model="llmDialogVisible" title="LLM 模型配置" width="560px" :close-on-click-modal="false" class="llm-config-dialog">
      <el-form label-width="120px" label-position="left">
        <el-form-item label="API Endpoint">
          <el-input v-model="llmForm.api_endpoint" placeholder="https://api.example.com/v1" />
        </el-form-item>
        <el-form-item label="API Key">
          <el-input v-model="llmForm.api_key" type="password" show-password placeholder="本地模型可留空" />
        </el-form-item>
        <el-form-item label="模型">
          <el-select
            v-if="!useCustomModel"
            v-model="llmForm.model"
            filterable
            allow-create
            default-first-option
            placeholder="从列表选择或手动输入"
            style="width: 100%"
            @change="handleModelChange"
            @visible-change="handleModelVisible"
          >
            <el-option label="自定义模型名称..." value="__custom__" />
            <el-option
              v-for="opt in llmModelOptions"
              :key="opt.value"
              :label="opt.label"
              :value="opt.value"
            />
          </el-select>
          <el-input v-else v-model="llmForm.model" placeholder="请输入自定义模型名称" style="width: 100%">
            <template #append>
              <el-button @click="useCustomModel = false; llmForm.model = ''">列表选择</el-button>
            </template>
          </el-input>
          <div v-if="llmForm.api_endpoint && !llmModelsLoaded && !useCustomModel" class="llm-model-hint">
            输入 Endpoint 和 Key 后自动获取模型列表
          </div>
        </el-form-item>
        <el-form-item label="Temperature">
          <el-input-number v-model="llmForm.temperature" :min="0" :max="2" :step="0.1" :precision="1" />
        </el-form-item>
        <el-form-item label="Max Tokens">
          <el-input-number v-model="llmForm.max_tokens" :min="100" :max="32000" :step="500" />
        </el-form-item>
        <el-form-item label="Timeout (秒)">
          <el-input-number v-model="llmForm.timeout" :min="10" :max="300" :step="10" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button :loading="llmTesting" @click="handleTestLLM">测试连接</el-button>
        <el-button @click="llmDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="llmSaving" @click="handleSaveLLM">保存并生效</el-button>
      </template>
    </el-dialog>

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

// 右列容器：存储优化 + LLM 模型，总高度与左列安全策略对齐
.config-right-col {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

// LLM 区块填充剩余高度，使 存储优化+LLM = 安全策略
.config-section-llm {
  flex: 1;
  display: flex;
  flex-direction: column;

  .llm-info {
    display: flex;
    align-items: center;
    gap: 12px;
  }
}

.llm-model-name {
  font-size: 14px;
  font-weight: 600;
  font-family: $font-mono;
  color: $color-text-primary;
}

.llm-model-empty {
  font-size: 13px;
  color: $color-text-secondary;
}

.llm-model-hint {
  font-size: 12px;
  color: $color-text-secondary;
  margin-top: 4px;
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

<!-- 非 scoped：el-dialog teleport 到 body，需全局样式 -->
<style lang="scss">
.llm-config-dialog {
  .el-form-item__label {
    font-family: $font-mono;
    font-feature-settings: 'tnum';
    font-weight: 600;
  }

  .el-input__inner,
  .el-input-number__decrease,
  .el-input-number__increase,
  .el-select__placeholder,
  .el-select__selected-item {
    font-family: $font-mono;
    font-feature-settings: 'tnum';
    font-weight: 600;
  }
}
</style>
