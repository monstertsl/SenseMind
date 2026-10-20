<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listAlertPresets } from '@/api/alertPreset'
import { describeAlertFilters } from '@/constants/alertFilters'
import {
  createAlertMailWatch,
  deleteAlertMailWatch,
  listAlertMailWatches,
  updateAlertMailWatch,
  type AlertMailWatch,
  type AlertMailWatchPayload,
  type MailWatchPeriod,
} from '@/api/alertMailWatch'
import { getMailConfig, sendTestMail, updateMailConfig, type MailConfig } from '@/api/mailConfig'
import { ALERT_FILTER_KEYS } from '@/constants/alertFilters'
import type { AlertSearchPreset } from '@/types'

const loading = ref(true)
const saving = ref(false)
const testing = ref(false)
const configDialogVisible = ref(false)
const testDialogVisible = ref(false)
const testRecipient = ref('')
const savedConfig = ref<MailConfig | null>(null)
const watches = ref<AlertMailWatch[]>([])
const presets = ref<AlertSearchPreset[]>([])
const watchDialogVisible = ref(false)
const savingWatch = ref(false)
const presetLoading = ref(false)
const editingWatchId = ref<number | null>(null)
const recipientInput = ref('')
const watchForm = reactive({
  preset_id: undefined as number | undefined,
  period: 'realtime' as MailWatchPeriod,
  daily_hour: 9,
  recipients: [] as string[],
})

const periodLabels: Record<MailWatchPeriod, string> = {
  realtime: '实时',
  '30m': '半小时',
  '2h': '2 小时',
  '4h': '4 小时',
  daily: '每天',
}

const emailAddressPattern = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/
const recipientInputInvalid = computed(() => {
  const value = recipientInput.value.trim()
  return Boolean(value && !emailAddressPattern.test(value))
})
const recipientCanAdd = computed(() => {
  const value = recipientInput.value.trim()
  return Boolean(value && emailAddressPattern.test(value))
})
const duplicateWatch = computed(() => {
  if (!watchForm.preset_id) return undefined
  const selectedPreset = presets.value.find((preset) => preset.id === watchForm.preset_id)
  if (!selectedPreset) return undefined
  const selectedFilters = normalizeFilters(selectedPreset.filters)
  return watches.value.find((watch) => {
    if (watch.id === editingWatchId.value || watch.period !== watchForm.period) return false
    const existingPreset = presets.value.find((preset) => preset.id === watch.preset_id)
    return existingPreset && normalizeFilters(existingPreset.filters) === selectedFilters
  })
})

const form = reactive({
  protocol: 'smtp' as MailConfig['protocol'],
  host: '',
  port: 587,
  username: '',
  password: '',
  use_ssl: false,
  sender_name: 'SenseMind安全管理平台',
})

const canTest = computed(() => Boolean(
  form.host.trim()
  && form.username.trim()
  && form.sender_name.trim()
  && (form.password || savedConfig.value?.password_configured),
))

function setForm(config: MailConfig) {
  form.protocol = config.protocol
  form.host = config.host
  form.port = config.port
  form.username = config.username
  form.password = ''
  form.use_ssl = config.use_ssl
  form.sender_name = config.sender_name
  savedConfig.value = { ...config }
}

async function loadConfig() {
  loading.value = true
  try {
    setForm(await getMailConfig())
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || error?.message || '邮件配置加载失败')
  } finally {
    loading.value = false
  }
}

async function loadMailWatches() {
  try {
    const [watchList, presetList] = await Promise.all([
      listAlertMailWatches(),
      listAlertPresets(),
    ])
    watches.value = watchList
    presets.value = presetList.items
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || error?.message || '关注告警加载失败')
  }
}

function normalizeFilters(filters: Partial<AlertSearchPreset['filters']>) {
  const normalized: Record<string, unknown> = {}
  const source = filters as Record<string, unknown>
  for (const key of ALERT_FILTER_KEYS) {
    const value = source[key]
    if (value !== undefined && value !== null && value !== '') normalized[key] = value
  }
  return JSON.stringify(normalized, Object.keys(normalized).sort())
}

function presetFilterSummary(presetId: number) {
  const preset = presets.value.find((item) => item.id === presetId)
  if (!preset) return '快捷检索不存在或已删除'
  return describeAlertFilters(preset.filters) || '（无筛选条件）'
}

function resetWatchForm(watch?: AlertMailWatch) {
  editingWatchId.value = watch?.id ?? null
  watchForm.preset_id = watch?.preset_id
  watchForm.period = watch?.period ?? 'realtime'
  watchForm.daily_hour = watch?.daily_hour ?? 9
  watchForm.recipients = [...(watch?.recipients ?? [])]
  recipientInput.value = ''
}

async function openWatchDialog(watch?: AlertMailWatch) {
  resetWatchForm(watch)
  watchDialogVisible.value = true
  presetLoading.value = true
  try {
    const [presetList, watchList] = await Promise.all([
      listAlertPresets(),
      listAlertMailWatches(),
    ])
    presets.value = presetList.items
    watches.value = watchList
    if (
      watchForm.preset_id
      && !presets.value.some((preset) => preset.id === watchForm.preset_id && preset.is_enabled)
    ) {
      watchForm.preset_id = undefined
    }
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || error?.message || '快捷检索加载失败')
  } finally {
    presetLoading.value = false
  }
}

function addRecipient() {
  const recipient = recipientInput.value.trim()
  if (!emailAddressPattern.test(recipient)) return
  if (!watchForm.recipients.includes(recipient)) {
    watchForm.recipients.push(recipient)
  }
  recipientInput.value = ''
}

function removeRecipient(recipient: string) {
  watchForm.recipients = watchForm.recipients.filter((item) => item !== recipient)
}

async function saveWatch() {
  if (recipientInput.value.trim()) {
    if (recipientInputInvalid.value) return
    addRecipient()
  }
  if (!watchForm.preset_id) {
    ElMessage.warning('请选择快捷检索')
    return
  }
  if (!watchForm.recipients.length) {
    ElMessage.warning('请至少添加一个收件邮箱')
    return
  }
  if (duplicateWatch.value) {
    ElMessage.warning(`已存在相同检索条件和发送周期的关注告警「${duplicateWatch.value.preset_name}」，不能重复保存`)
    return
  }
  const recipients = watchForm.recipients.map((recipient) => recipient.trim())
  const invalidRecipient = recipients.find((recipient) => !emailAddressPattern.test(recipient))
  if (invalidRecipient) {
    ElMessage.warning(`邮箱格式无效：${invalidRecipient}`)
    return
  }
  const payload: AlertMailWatchPayload = {
    preset_id: watchForm.preset_id,
    period: watchForm.period,
    daily_hour: watchForm.period === 'daily' ? watchForm.daily_hour : null,
    recipients,
  }

  savingWatch.value = true
  try {
    if (editingWatchId.value) {
      await updateAlertMailWatch(editingWatchId.value, payload)
    } else {
      await createAlertMailWatch(payload)
    }
    ElMessage.success(editingWatchId.value ? '关注告警已更新' : '关注告警已添加')
    watchDialogVisible.value = false
    await loadMailWatches()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || error?.message || '关注告警保存失败')
  } finally {
    savingWatch.value = false
  }
}

async function removeWatch(watch: AlertMailWatch) {
  try {
    await ElMessageBox.confirm(`确认删除「${watch.preset_name}」关注告警吗？`, '删除关注告警', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
    await deleteAlertMailWatch(watch.id)
    ElMessage.success('关注告警已删除')
    await loadMailWatches()
  } catch (error: any) {
    if (error !== 'cancel' && error !== 'close') {
      ElMessage.error(error?.response?.data?.detail || error?.message || '关注告警删除失败')
    }
  }
}

function formatRecipients(recipients: string[]) {
  return recipients.join('、')
}

function handleProtocolChange(protocol: MailConfig['protocol']) {
  if (protocol === 'smtps') {
    form.use_ssl = true
    if (form.port === 587) form.port = 465
  } else if (form.port === 465) {
    form.port = 587
  }
}

function openConfigDialog() {
  if (savedConfig.value) setForm(savedConfig.value)
  configDialogVisible.value = true
}

async function handleSave() {
  if (!form.host.trim() || !form.username.trim() || !form.sender_name.trim()) {
    ElMessage.warning('请填写邮件服务器、发件邮箱和显示名称')
    return
  }
  if (!savedConfig.value?.password_configured && !form.password) {
    ElMessage.warning('请填写 SMTP 密码')
    return
  }

  saving.value = true
  try {
    const config = await updateMailConfig({
      protocol: form.protocol,
      host: form.host.trim(),
      port: Number(form.port),
      username: form.username.trim(),
      password: form.password,
      use_ssl: form.use_ssl,
      sender_name: form.sender_name.trim(),
    })
    setForm(config)
    ElMessage.success('邮件配置已保存')
    configDialogVisible.value = false
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || error?.message || '邮件配置保存失败')
  } finally {
    saving.value = false
  }
}

function openTestDialog() {
  testRecipient.value = ''
  testDialogVisible.value = true
}

async function handleTestMail() {
  if (!testRecipient.value.trim()) {
    ElMessage.warning('请输入目标邮箱')
    return
  }

  testing.value = true
  try {
    await sendTestMail(testRecipient.value.trim(), {
      protocol: form.protocol,
      host: form.host.trim(),
      port: Number(form.port),
      username: form.username.trim(),
      password: form.password,
      use_ssl: form.use_ssl,
      sender_name: form.sender_name.trim(),
    })
    ElMessage.success('测试邮件已发送，请检查收件箱')
    testDialogVisible.value = false
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || error?.message || '测试邮件发送失败')
  } finally {
    testing.value = false
  }
}

onMounted(() => {
  loadConfig()
  loadMailWatches()
})
</script>

<template>
  <div class="outbound-page">
    <section v-loading="loading" class="section-block">
      <div class="block-title-row">
        <div class="block-title">邮件告警</div>
        <el-button v-if="savedConfig?.password_configured" type="primary" @click="openConfigDialog">
          修改发件邮箱配置
        </el-button>
        <el-button
          v-else-if="!loading"
          type="primary"
          @click="openConfigDialog"
        >
          配置发件邮箱
        </el-button>
      </div>

      <div class="mail-config-row">
        <div class="mail-config-summary">
          <span class="config-label">关注告警配置</span>
          <span class="watch-count">{{ watches.length }} 条</span>
        </div>
        <div class="row-actions">
          <el-button type="primary" @click="openWatchDialog()">添加关注告警</el-button>
        </div>
      </div>

      <el-table v-if="watches.length" :data="watches" row-key="id" class="watch-table">
        <el-table-column label="检索条件" min-width="150">
          <template #default="scope">
            <el-tooltip :content="presetFilterSummary(scope.row.preset_id)" placement="top" :show-after="200">
              <span class="preset-condition">{{ scope.row.preset_name }}</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="发送周期" width="120">
          <template #default="scope">
            {{ periodLabels[scope.row.period as MailWatchPeriod] }}<template v-if="scope.row.period === 'daily'"> {{ scope.row.daily_hour }}:00</template>
          </template>
        </el-table-column>
        <el-table-column label="收件邮箱" min-width="220" show-overflow-tooltip>
          <template #default="scope">{{ formatRecipients(scope.row.recipients) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="130" fixed="right">
          <template #default="scope">
            <el-button link type="primary" @click="openWatchDialog(scope.row)">编辑</el-button>
            <el-button link type="danger" @click="removeWatch(scope.row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-else class="watch-empty">暂无关注告警，点击「添加关注告警」添加</div>
    </section>

    <el-dialog
      v-model="watchDialogVisible"
      width="560px"
      :close-on-click-modal="false"
    >
      <template #header>
        <strong class="watch-dialog-title">{{ editingWatchId ? '编辑关注告警' : '添加关注告警' }}</strong>
      </template>
      <el-form label-position="top" @submit.prevent>
        <el-form-item label="检索条件" required>
          <el-select
            v-model="watchForm.preset_id"
            placeholder="选择已启用的快捷检索"
            filterable
            :loading="presetLoading"
          >
            <el-option
              v-for="preset in presets.filter((item) => item.is_enabled)"
              :key="preset.id"
              :label="preset.name"
              :value="preset.id"
            />
          </el-select>
          <div v-if="!presets.length" class="form-hint">暂无可用快捷检索，请先在分析中心保存检索条件。</div>
        </el-form-item>
        <el-form-item label="发送周期" required>
          <el-select v-model="watchForm.period">
            <el-option label="实时" value="realtime" />
            <el-option label="半小时" value="30m" />
            <el-option label="2 小时" value="2h" />
            <el-option label="4 小时" value="4h" />
            <el-option label="每天" value="daily" />
          </el-select>
        </el-form-item>
        <el-alert
          v-if="duplicateWatch && !presetLoading"
          class="duplicate-watch-alert"
          type="warning"
          :closable="false"
          show-icon
          :title="`已存在相同检索条件和发送周期的关注告警「${duplicateWatch.preset_name}」，不能重复保存`"
        />
        <el-form-item v-if="watchForm.period === 'daily'" label="发送时间（北京时间，整点）" required>
          <el-select v-model="watchForm.daily_hour">
            <el-option v-for="hour in 24" :key="hour - 1" :label="`${String(hour - 1).padStart(2, '0')}:00`" :value="hour - 1" />
          </el-select>
        </el-form-item>
        <el-form-item label="收件邮箱" required>
          <div class="recipient-field">
            <el-input
              v-model="recipientInput"
              type="email"
              placeholder="输入邮箱地址，按Enter键添加"
              :class="{ 'recipient-input-invalid': recipientInputInvalid }"
              @keyup.enter.prevent="addRecipient"
            >
              <template #append>
                <el-button :disabled="!recipientCanAdd" @click="addRecipient">添加</el-button>
              </template>
            </el-input>
            <div v-if="recipientInputInvalid" class="recipient-error">
              邮箱格式不正确，请输入 name@example.com 格式
            </div>
            <div v-if="watchForm.recipients.length" class="recipient-tags">
              <el-tag
                v-for="recipient in watchForm.recipients"
                :key="recipient"
                closable
                @close="removeRecipient(recipient)"
              >
                {{ recipient }}
              </el-tag>
            </div>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="watchDialogVisible = false">取消</el-button>
        <el-button
          type="primary"
          :loading="savingWatch"
          :disabled="presetLoading || !!duplicateWatch"
          @click="saveWatch"
        >保存</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="configDialogVisible"
      width="600px"
      :close-on-click-modal="false"
    >
      <template #header>
        <span class="dialog-title">邮件配置</span>
      </template>
      <el-form label-position="top" @submit.prevent>
        <div class="form-grid">
          <el-form-item label="协议">
            <el-select v-model="form.protocol" @change="handleProtocolChange">
              <el-option label="SMTP" value="smtp" />
              <el-option label="SMTPS" value="smtps" />
            </el-select>
          </el-form-item>
          <el-form-item label="邮件服务器地址">
            <el-input v-model="form.host" placeholder="smtp.example.com" autocomplete="off" />
          </el-form-item>
          <el-form-item label="端口">
            <el-input-number v-model="form.port" class="port-input" :min="1" :max="65535" :controls="false" />
          </el-form-item>
          <el-form-item label="用户名">
            <el-input v-model="form.username" placeholder="alerts@example.com" autocomplete="username" />
          </el-form-item>
          <el-form-item label="密码">
            <el-input
              v-model="form.password"
              type="password"
              show-password
              autocomplete="new-password"
              :placeholder="savedConfig?.password_configured ? '留空以保留现有密码' : '请输入 SMTP 密码'"
            />
          </el-form-item>
          <el-form-item label="使用 SSL/TLS">
            <div class="ssl-control">
              <el-switch v-model="form.use_ssl" :disabled="form.protocol === 'smtps'" />
              <span>{{ form.protocol === 'smtps' ? 'SMTPS 使用隐式 TLS' : 'SMTP 启用时使用 STARTTLS' }}</span>
            </div>
          </el-form-item>
          <el-form-item label="发件人显示名称" class="sender-name-item">
            <el-input v-model="form.sender_name" maxlength="100" show-word-limit placeholder="SenseMind安全管理平台" />
          </el-form-item>
        </div>
      </el-form>
      <template #footer>
        <div class="config-dialog-footer">
          <el-button :disabled="!canTest" @click="openTestDialog">发送测试邮件</el-button>
          <div class="footer-actions-right">
            <el-button @click="configDialogVisible = false">取消</el-button>
            <el-button type="primary" :loading="saving" @click="handleSave">保存配置</el-button>
          </div>
        </div>
      </template>
    </el-dialog>

    <el-dialog
      v-model="testDialogVisible"
      title="发送测试邮件"
      width="420px"
      :close-on-click-modal="false"
    >
      <el-form @submit.prevent="handleTestMail">
        <el-form-item label="目标邮箱">
          <el-input
            v-model="testRecipient"
            type="email"
            placeholder="name@example.com"
            autocomplete="email"
            @keyup.enter="handleTestMail"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="testDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="testing" @click="handleTestMail">发送</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped lang="scss">
.outbound-page {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.section-block {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 18px 20px;
  border: 1px solid #e4e7ed;
  border-radius: $radius-md;
  background: $color-bg-elevated;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
}

.block-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.block-title {
  padding-left: 10px;
  border-left: 4px solid $color-primary;
  color: $color-text-primary;
  font-size: 15px;
  font-weight: 700;
}

.mail-config-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  min-height: 56px;
  padding: 8px 0 0;
  border-top: 1px solid $color-border;
}

.mail-config-summary {
  display: flex;
  min-width: 0;
  align-items: center;
  flex-wrap: wrap;
  gap: 18px;
}

.watch-count,
.form-hint {
  color: $color-text-secondary;
  font-size: 12px;
}

.watch-table {
  width: 100%;
  border-top: 1px solid $color-border;
}

.watch-empty {
  padding: 28px 12px;
  border-top: 1px solid $color-border;
  color: $color-text-secondary;
  font-size: 13px;
  text-align: center;
}

.preset-condition {
  cursor: default;
}

.watch-dialog-title {
  color: $color-text-primary;
  font-size: 16px;
  font-weight: 700;
}

.form-hint {
  margin-top: 6px;
}

.recipient-field {
  width: 100%;
}

.recipient-input-invalid :deep(.el-input__wrapper) {
  box-shadow: 0 0 0 1px $color-danger inset;
}

.recipient-error {
  margin-top: 5px;
  color: $color-danger;
  font-size: 12px;
  line-height: 1.4;
}

.recipient-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}

.config-label {
  color: $color-text-regular;
  font-size: 13px;
  font-weight: 600;
}

.dialog-title {
  color: $color-text-primary;
  font-size: 16px;
  font-weight: 700;
}

.row-actions {
  display: flex;
  flex: 0 0 auto;
  gap: 8px;
}

.config-dialog-footer,
.footer-actions-right {
  display: flex;
  align-items: center;
}

.config-dialog-footer {
  justify-content: space-between;
}

.footer-actions-right {
  gap: 8px;
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  column-gap: 24px;
}

.port-input {
  width: 100%;

  :deep(.el-input__inner) {
    text-align: left;
  }
}

.ssl-control {
  display: flex;
  min-height: 32px;
  align-items: center;
  gap: 10px;
  color: $color-text-secondary;
  font-size: 12px;
}

@media (max-width: 700px) {
  .section-block {
    padding: 16px;
  }

  .form-grid {
    grid-template-columns: 1fr;
  }

  .mail-config-row {
    align-items: flex-start;
    flex-direction: column;
  }

  .row-actions {
    width: 100%;
  }

  .sender-name-item {
    grid-column: 1;
  }
}
</style>