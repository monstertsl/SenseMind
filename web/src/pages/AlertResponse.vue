<script setup lang="ts">
// 联动处置面板：作为「联动外发」页（/outbound）的子区块使用，无独立路由
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Upload } from '@element-plus/icons-vue'
import {
  createResponseDevice,
  deleteResponseDevice,
  deleteResponseDriverScript,
  downloadExampleDriver,
  listResponseDevices,
  listResponseDrivers,
  testResponseDeviceConfig,
  testSavedResponseDevice,
  updateResponseDevice,
  uploadResponseDriver,
  type ConfigField,
  type DriverManifest,
  type ResponseDeviceItem,
} from '@/api/responseDevice'
import {
  createResponseTask,
  deleteResponseTask,
  listResponseTasks,
  updateResponseTask,
  type ResponseTaskItem,
} from '@/api/responseTask'
import {
  createResponseWhitelist,
  deleteResponseWhitelist,
  listResponseWhitelist,
  type WhitelistItem,
} from '@/api/responseWhitelist'
import { listAlertPresets } from '@/api/alertPreset'
import SkeletonTable from '@/components/common/SkeletonTable.vue'
import type { AlertSearchPreset } from '@/types'

const loading = ref(false)
const drivers = ref<DriverManifest[]>([])
const devices = ref<ResponseDeviceItem[]>([])
const tasks = ref<ResponseTaskItem[]>([])
const whitelist = ref<WhitelistItem[]>([])
const presets = ref<AlertSearchPreset[]>([])

const deviceDialogVisible = ref(false)
const editingId = ref<number | null>(null)
const testing = ref(false)
const saving = ref(false)
const uploading = ref(false)
const downloadingExample = ref(false)
const scriptInput = ref<HTMLInputElement | null>(null)
const scriptDialogVisible = ref(false)

const taskDialogVisible = ref(false)
const editingTaskId = ref<number | null>(null)
const taskSaving = ref(false)
const taskForm = reactive({ name: '', device_id: null as number | null, preset_id: null as number | null })

const whitelistDialogVisible = ref(false)
const whitelistForm = reactive({ value: '', note: '' })

const form = reactive({
  name: '',
  driver: '',
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  config: {} as Record<string, any>,
})

const currentDriver = computed(() => drivers.value.find((item) => item.key === form.driver))
const customDrivers = computed(() => drivers.value.filter((item) => item.custom))
const currentFields = computed<ConfigField[]>(() => currentDriver.value?.config_schema || [])
const enabledDevices = computed(() => devices.value.filter((item) => item.enabled))
const enabledPresets = computed(() => presets.value.filter((item) => item.is_enabled))

const presetNames = computed(() => {
  const map: Record<number, string> = {}
  for (const preset of presets.value) map[preset.id] = preset.name
  return map
})

function fieldVisible(field: ConfigField): boolean {
  if (!field.depends_on) return true
  return Object.entries(field.depends_on).every(
    ([key, expected]) => String(form.config[key] ?? '') === String(expected),
  )
}

function errorText(error: unknown, fallback: string): string {
  const detail = (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail
  return detail || (error as Error)?.message || fallback
}

function applyDefaults() {
  const config: Record<string, unknown> = {}
  for (const field of currentFields.value) {
    if (field.default !== undefined) config[field.name] = field.default
  }
  form.config = config
}

async function loadAll() {
  try {
    const [driverData, deviceData, taskData, whitelistData, presetData] = await Promise.all([
      listResponseDrivers(),
      listResponseDevices(),
      listResponseTasks(),
      listResponseWhitelist(),
      listAlertPresets(),
    ])
    drivers.value = driverData.items || []
    devices.value = deviceData.items || []
    tasks.value = taskData.items || []
    whitelist.value = whitelistData.items || []
    presets.value = presetData.items || []
  } catch (error) {
    ElMessage.error(errorText(error, '加载联动处置数据失败'))
  }
}

async function refreshAll() {
  loading.value = true
  try {
    await loadAll()
  } finally {
    loading.value = false
  }
}

// ---- 设备 ----

function openCreate() {
  editingId.value = null
  form.name = ''
  form.driver = drivers.value[0]?.key || ''
  applyDefaults()
  deviceDialogVisible.value = true
}

function openEdit(row: ResponseDeviceItem) {
  editingId.value = row.id
  form.name = row.name
  form.driver = row.driver
  form.config = { ...row.config }
  deviceDialogVisible.value = true
}

function onDriverChange() {
  if (editingId.value === null) applyDefaults()
}

function pickScript() {
  scriptInput.value?.click()
}

async function reloadDrivers(selectKey?: string) {
  const data = await listResponseDrivers()
  drivers.value = data.items || []
  if (selectKey) {
    form.driver = selectKey
    applyDefaults()
  }
}

async function onScriptPicked(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  uploading.value = true
  try {
    const manifest = await uploadResponseDriver(file)
    await reloadDrivers(manifest.key)
    ElMessage.success(`脚本已上传：${manifest.display_name}`)
  } catch (error) {
    const detail = errorText(error, '上传脚本失败')
    if (!detail.includes('已存在同名脚本')) {
      ElMessage.error(detail)
      return
    }
    try {
      await ElMessageBox.confirm(
        `${detail}。覆盖后使用该设备类型的设备会立即改用新脚本。`,
        '覆盖脚本',
        { type: 'warning', confirmButtonText: '覆盖' },
      )
    } catch {
      return
    }
    try {
      const manifest = await uploadResponseDriver(file, true)
      await reloadDrivers(manifest.key)
      ElMessage.success(`脚本已覆盖：${manifest.display_name}`)
    } catch (err) {
      ElMessage.error(errorText(err, '覆盖脚本失败'))
    }
  } finally {
    uploading.value = false
  }
}

function openScriptManager() {
  scriptDialogVisible.value = true
}

async function removeScript(row: DriverManifest) {
  try {
    await ElMessageBox.confirm(
      `删除后，使用「${row.display_name}」的设备将无法再下发封堵，相关联动处置会失败。`,
      '删除自定义脚本',
      { type: 'warning', confirmButtonText: '删除' },
    )
  } catch {
    return
  }
  try {
    await deleteResponseDriverScript(row.key)
    await reloadDrivers()
    if (form.driver === row.key) {
      form.driver = drivers.value[0]?.key || ''
      applyDefaults()
    }
    ElMessage.success(`已删除脚本 ${row.key}.py`)
  } catch (error) {
    ElMessage.error(errorText(error, '删除脚本失败'))
  }
}

async function downloadExample() {
  downloadingExample.value = true
  try {
    const data = await downloadExampleDriver()
    const blob = new Blob([data.content], { type: 'text/x-python;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = data.filename || 'example_vendor.py'
    link.click()
    URL.revokeObjectURL(url)
  } catch (error) {
    ElMessage.error(errorText(error, '下载示例脚本失败'))
  } finally {
    downloadingExample.value = false
  }
}

function secretPlaceholder(field: ConfigField): string {
  if (!field.secret) return field.placeholder || ''
  const editing = devices.value.find((item) => item.id === editingId.value)
  return editing?.secret_configured?.[field.name] ? '留空以保留现有值' : '请输入'
}

function collectConfig(requireSecrets: boolean): Record<string, unknown> | null {
  const editing = devices.value.find((item) => item.id === editingId.value)
  for (const field of currentFields.value) {
    if (!fieldVisible(field) || !field.required) continue
    const value = form.config[field.name]
    if (value !== undefined && value !== null && String(value).trim() !== '') continue
    if (field.secret && !requireSecrets && editing?.secret_configured?.[field.name]) continue
    ElMessage.warning(`请填写${field.label}`)
    return null
  }
  const config: Record<string, unknown> = {}
  for (const field of currentFields.value) {
    if (!fieldVisible(field)) continue
    const value = form.config[field.name]
    if (value === undefined || value === null || String(value).trim() === '') continue
    config[field.name] = value
  }
  if (form.config.verify_tls !== undefined) config.verify_tls = form.config.verify_tls
  if (form.config.timeout_seconds !== undefined && String(form.config.timeout_seconds).trim() !== '') {
    config.timeout_seconds = form.config.timeout_seconds
  }
  return config
}

function validateDeviceForm(): boolean {
  if (!form.name.trim()) {
    ElMessage.warning('请填写设备名称')
    return false
  }
  if (!form.driver) {
    ElMessage.warning('请选择设备类型')
    return false
  }
  return true
}

async function runTest() {
  if (!validateDeviceForm()) return
  const config = collectConfig(false)
  if (!config) return
  testing.value = true
  try {
    const result = await testResponseDeviceConfig({ driver: form.driver, config })
    if (result.ok) ElMessage.success(result.message || '连接成功')
    else ElMessage.error(result.message || '连接失败')
  } catch (error) {
    ElMessage.error(errorText(error, '连接测试失败'))
  } finally {
    testing.value = false
  }
}

async function testSaved(row: ResponseDeviceItem) {
  try {
    const result = await testSavedResponseDevice(row.id)
    if (result.ok) ElMessage.success(`${row.name}：${result.message || '连接成功'}`)
    else ElMessage.error(`${row.name}：${result.message || '连接失败'}`)
  } catch (error) {
    ElMessage.error(errorText(error, '连接测试失败'))
  }
}

async function saveDevice() {
  if (!validateDeviceForm()) return
  const config = collectConfig(true)
  if (!config) return
  saving.value = true
  try {
    if (editingId.value === null) {
      await createResponseDevice({ name: form.name.trim(), driver: form.driver, config })
    } else {
      await updateResponseDevice(editingId.value, { name: form.name.trim(), config })
    }
    ElMessage.success('设备已保存')
    deviceDialogVisible.value = false
    await loadAll()
  } catch (error) {
    ElMessage.error(errorText(error, '保存设备失败'))
  } finally {
    saving.value = false
  }
}

async function toggleDevice(row: ResponseDeviceItem) {
  try {
    await updateResponseDevice(row.id, { enabled: !row.enabled })
    await loadAll()
  } catch (error) {
    ElMessage.error(errorText(error, '切换设备状态失败'))
  }
}

async function removeDevice(row: ResponseDeviceItem) {
  try {
    await ElMessageBox.confirm(`确认删除设备「${row.name}」？`, '删除确认', { type: 'warning' })
  } catch {
    return
  }
  try {
    await deleteResponseDevice(row.id)
    ElMessage.success('设备已删除')
    await loadAll()
  } catch (error) {
    ElMessage.error(errorText(error, '删除设备失败'))
  }
}

// ---- 联动设置 ----

function openTaskDialog(row?: ResponseTaskItem) {
  if (!enabledDevices.value.length) {
    ElMessage.warning('请先添加并启用联动处置设备')
    return
  }
  editingTaskId.value = row?.id ?? null
  taskForm.name = row?.name || ''
  taskForm.device_id = row?.device_id ?? enabledDevices.value[0]?.id ?? null
  taskForm.preset_id = row?.preset_id ?? enabledPresets.value[0]?.id ?? null
  taskDialogVisible.value = true
}

async function saveTask() {
  if (!taskForm.name.trim()) {
    ElMessage.warning('请填写联动设置名称')
    return
  }
  if (!taskForm.device_id) {
    ElMessage.warning('请选择联动处置设备')
    return
  }
  if (!taskForm.preset_id) {
    ElMessage.warning('请选择命中条件（快捷检索）')
    return
  }
  taskSaving.value = true
  const payload = {
    name: taskForm.name.trim(),
    device_id: taskForm.device_id,
    preset_id: taskForm.preset_id,
  }
  try {
    if (editingTaskId.value === null) await createResponseTask(payload)
    else await updateResponseTask(editingTaskId.value, payload)
    ElMessage.success('联动设置已保存')
    taskDialogVisible.value = false
    await loadAll()
  } catch (error) {
    ElMessage.error(errorText(error, '保存联动设置失败'))
  } finally {
    taskSaving.value = false
  }
}

async function toggleTask(row: ResponseTaskItem) {
  try {
    await updateResponseTask(row.id, { enabled: !row.enabled })
    await loadAll()
  } catch (error) {
    ElMessage.error(errorText(error, '切换联动设置状态失败'))
  }
}

async function removeTask(row: ResponseTaskItem) {
  try {
    await ElMessageBox.confirm(`确认删除联动设置「${row.name}」？`, '删除确认', { type: 'warning' })
  } catch {
    return
  }
  try {
    await deleteResponseTask(row.id)
    ElMessage.success('联动设置已删除')
    await loadAll()
  } catch (error) {
    ElMessage.error(errorText(error, '删除联动设置失败'))
  }
}

// ---- 白名单 ----

function openWhitelist() {
  whitelistForm.value = ''
  whitelistForm.note = ''
  whitelistDialogVisible.value = true
}

async function saveWhitelist() {
  if (!whitelistForm.value.trim()) {
    ElMessage.warning('请填写 IP 或 CIDR')
    return
  }
  try {
    await createResponseWhitelist({
      value: whitelistForm.value.trim(),
      note: whitelistForm.note.trim(),
    })
    ElMessage.success('白名单已添加')
    whitelistDialogVisible.value = false
    await loadAll()
  } catch (error) {
    ElMessage.error(errorText(error, '添加白名单失败'))
  }
}

async function removeWhitelist(row: WhitelistItem) {
  try {
    await ElMessageBox.confirm(`确认移出白名单「${row.value}」？`, '删除确认', { type: 'warning' })
  } catch {
    return
  }
  try {
    await deleteResponseWhitelist(row.id)
    ElMessage.success('白名单已删除')
    await loadAll()
  } catch (error) {
    ElMessage.error(errorText(error, '删除白名单失败'))
  }
}

function deviceSummary(row: ResponseDeviceItem): string {
  const base = String(row.config.base_url || row.config.endpoint || '')
  const namespace = row.config.namespace ? ` / ${row.config.namespace}` : ''
  return `${base}${namespace}` || '—'
}

function presetName(presetId: number): string {
  return presetNames.value[presetId] || `#${presetId}`
}

onMounted(refreshAll)
</script>

<template>
  <div class="response-page">
    <section class="section-block">
      <div class="block-title-row">
        <div class="block-title">联动处置</div>
        <div class="row-actions">
          <el-button :icon="Plus" :disabled="!drivers.length" @click="openCreate">
            添加联动设备
          </el-button>
          <el-button type="primary" :icon="Plus" @click="openTaskDialog()">添加联动处置</el-button>
        </div>
      </div>

      <div class="sub-block">
        <div class="sub-title">联动设置</div>
        <SkeletonTable v-if="loading" :rows="2" :columns="5" />
        <el-table v-else-if="tasks.length" :data="tasks" row-key="id">
          <el-table-column prop="name" label="名称" min-width="140" />
          <el-table-column prop="device_name" label="封堵设备" min-width="140" />
          <el-table-column label="命中条件" min-width="160" show-overflow-tooltip>
            <template #default="scope">{{ presetName(scope.row.preset_id) }}</template>
          </el-table-column>
          <el-table-column label="状态" width="90">
            <template #default="scope">
              <el-tag :type="scope.row.enabled ? 'success' : 'info'" size="small">
                {{ scope.row.enabled ? '启用' : '停用' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="190" fixed="right">
            <template #default="scope">
              <el-button link type="primary" @click="openTaskDialog(scope.row)">编辑</el-button>
              <el-button link type="primary" @click="toggleTask(scope.row)">
                {{ scope.row.enabled ? '停用' : '启用' }}
              </el-button>
              <el-button link type="danger" @click="removeTask(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <div v-else class="empty-tip">
          暂无联动设置。命中快捷检索条件后，源 IP 将被送到所选设备封堵。
        </div>
      </div>

      <div class="sub-block">
        <div class="sub-title">已接入设备</div>
        <SkeletonTable v-if="loading" :rows="2" :columns="5" />
        <el-table v-else-if="devices.length" :data="devices" row-key="id">
          <el-table-column prop="name" label="设备名称" min-width="160" />
          <el-table-column prop="display_name" label="设备类型" width="150" />
          <el-table-column label="地址" min-width="200" show-overflow-tooltip>
            <template #default="scope">{{ deviceSummary(scope.row) }}</template>
          </el-table-column>
          <el-table-column label="状态" width="90">
            <template #default="scope">
              <el-tag :type="scope.row.enabled ? 'success' : 'info'" size="small">
                {{ scope.row.enabled ? '启用' : '停用' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="250" fixed="right">
            <template #default="scope">
              <el-button link type="primary" @click="testSaved(scope.row)">测试连接</el-button>
              <el-button link type="primary" @click="openEdit(scope.row)">编辑</el-button>
              <el-button link type="primary" @click="toggleDevice(scope.row)">
                {{ scope.row.enabled ? '停用' : '启用' }}
              </el-button>
              <el-button link type="danger" @click="removeDevice(scope.row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <div v-else class="empty-tip">
          暂无设备，点击右上角「添加联动设备」接入防火墙。当前可用类型：
          {{ drivers.map((item) => item.display_name).join('、') || '无' }}
        </div>
      </div>
    </section>

    <section class="section-block">
      <div class="block-title-row">
        <div class="block-title">IP 白名单</div>
        <el-button type="primary" :icon="Plus" @click="openWhitelist">添加白名单</el-button>
      </div>
      <div class="block-hint">命中白名单的源 IP 不会触发封堵，支持单个 IP 或 CIDR。</div>

      <SkeletonTable v-if="loading" :rows="2" :columns="3" />
      <el-table v-else-if="whitelist.length" :data="whitelist" row-key="id">
        <el-table-column prop="value" label="IP / CIDR" min-width="200" />
        <el-table-column prop="note" label="备注" min-width="200" show-overflow-tooltip />
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="scope">
            <el-button link type="danger" @click="removeWhitelist(scope.row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-else class="empty-tip">暂无白名单</div>
    </section>

    <el-dialog v-model="taskDialogVisible" width="560px" :close-on-click-modal="false">
      <template #header>
        <strong class="dialog-title">{{ editingTaskId === null ? '添加联动处置' : '编辑联动处置' }}</strong>
      </template>
      <el-form label-position="top" @submit.prevent>
        <el-form-item label="名称" required>
          <el-input v-model="taskForm.name" placeholder="例如：外网暴力破解封堵" maxlength="100" />
        </el-form-item>
        <el-form-item label="封堵设备" required>
          <el-select v-model="taskForm.device_id" placeholder="选择已启用的设备">
            <el-option
              v-for="device in enabledDevices"
              :key="device.id"
              :label="`${device.name}（${device.display_name}）`"
              :value="device.id"
            />
          </el-select>
          <div v-if="!enabledDevices.length" class="field-help">暂无启用设备，请先添加设备。</div>
        </el-form-item>
        <el-form-item label="命中条件（快捷检索）" required>
          <el-select v-model="taskForm.preset_id" placeholder="选择已启用的快捷检索" filterable>
            <el-option
              v-for="preset in enabledPresets"
              :key="preset.id"
              :label="preset.name"
              :value="preset.id"
            />
          </el-select>
          <div v-if="!enabledPresets.length" class="field-help">
            暂无可用快捷检索，请先在分析中心保存检索条件。
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="taskDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="taskSaving" @click="saveTask">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="deviceDialogVisible" width="600px" :close-on-click-modal="false">
      <template #header>
        <div class="dialog-header">
          <strong class="dialog-title">
            {{ editingId === null ? '添加联动设备' : '编辑联动设备' }}
          </strong>
          <div v-if="editingId === null" class="dialog-header-actions">
            <el-button size="small" :icon="Upload" :loading="uploading" @click="pickScript">
              上传脚本
            </el-button>
            <el-button
              size="small"
              link
              type="primary"
              :loading="downloadingExample"
              @click="downloadExample"
            >
              下载示例
            </el-button>
            <el-button size="small" link @click="openScriptManager">管理脚本</el-button>
          </div>
          <input
            ref="scriptInput"
            type="file"
            accept=".py"
            class="hidden-file"
            @change="onScriptPicked"
          />
        </div>
      </template>
      <el-form label-position="top" @submit.prevent>
        <el-form-item label="设备名称" required>
          <el-input v-model="form.name" placeholder="例如：出口防火墙-主" maxlength="100" />
        </el-form-item>
        <el-form-item label="设备类型" required>
          <el-select
            v-model="form.driver"
            :disabled="editingId !== null"
            placeholder="选择设备类型"
            @change="onDriverChange"
          >
            <el-option
              v-for="driver in drivers"
              :key="driver.key"
              :label="driver.display_name"
              :value="driver.key"
            />
          </el-select>
        </el-form-item>

        <template v-for="field in currentFields" :key="field.name">
          <el-form-item v-if="fieldVisible(field)" :label="field.label" :required="field.required">
            <el-switch v-if="field.type === 'bool'" v-model="form.config[field.name]" />
            <el-input-number
              v-else-if="field.type === 'int'"
              v-model="form.config[field.name]"
              :min="0"
              controls-position="right"
            />
            <el-select
              v-else-if="field.type === 'select'"
              v-model="form.config[field.name]"
              :placeholder="field.placeholder || '请选择'"
            >
              <el-option
                v-for="choice in field.choices || []"
                :key="choice"
                :label="choice"
                :value="choice"
              />
            </el-select>
            <el-input
              v-else-if="field.type === 'textarea'"
              v-model="form.config[field.name]"
              type="textarea"
              :rows="3"
              :placeholder="field.placeholder || ''"
            />
            <el-input
              v-else
              v-model="form.config[field.name]"
              :type="field.type === 'password' ? 'password' : 'text'"
              :show-password="field.type === 'password'"
              :autocomplete="field.type === 'password' ? 'new-password' : 'off'"
              :placeholder="secretPlaceholder(field)"
            />
            <div v-if="field.help" class="field-help">{{ field.help }}</div>
          </el-form-item>
        </template>

        <el-divider content-position="left">高级选项</el-divider>
        <div class="advanced-row">
          <div class="advanced-item">
            <span class="advanced-label">校验证书</span>
            <el-switch v-model="form.config.verify_tls" />
          </div>
          <div class="advanced-item">
            <span class="advanced-label">超时（秒）</span>
            <el-input-number
              v-model="form.config.timeout_seconds"
              :min="1"
              :max="120"
              controls-position="right"
            />
          </div>
        </div>
        <div class="field-help">自签证书设备需关闭校验证书；超时留空按平台默认值。</div>
      </el-form>

      <template #footer>
        <el-button :loading="testing" @click="runTest">测试连接</el-button>
        <el-button @click="deviceDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveDevice">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="scriptDialogVisible" width="660px" :close-on-click-modal="false">
      <template #header>
        <strong class="dialog-title">自定义设备脚本</strong>
      </template>
      <el-table :data="customDrivers" size="small" empty-text="暂无自定义脚本">
        <el-table-column label="设备类型" prop="display_name" min-width="150" />
        <el-table-column label="文件名" min-width="140">
          <template #default="{ row }">{{ row.key }}.py</template>
        </el-table-column>
        <el-table-column label="上传时间" min-width="160">
          <template #default="{ row }">{{ row.meta?.uploaded_at || '未知' }}</template>
        </el-table-column>
        <el-table-column label="上传人" min-width="100">
          <template #default="{ row }">{{ row.meta?.uploaded_by || '未知' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="90">
          <template #default="{ row }">
            <el-button link type="danger" @click="removeScript(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="field-help">
        自定义脚本以服务进程权限执行，等价于允许上传者在服务端运行代码；删除脚本不会删除已保存的设备。
      </div>
      <template #footer>
        <el-button @click="scriptDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="whitelistDialogVisible" width="460px" :close-on-click-modal="false">
      <template #header>
        <strong class="dialog-title">添加白名单</strong>
      </template>
      <el-form label-position="top" @submit.prevent>
        <el-form-item label="IP 或 CIDR" required>
          <el-input v-model="whitelistForm.value" placeholder="例如：10.10.10.10 或 10.10.10.0/24" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="whitelistForm.note" maxlength="200" placeholder="选填" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="whitelistDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="saveWhitelist">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped lang="scss">
.response-page {
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

.row-actions {
  display: flex;
  gap: 8px;
}

.sub-block {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.sub-title {
  color: $color-text-primary;
  font-size: 13px;
  font-weight: 600;
}

.block-hint,
.empty-tip {
  color: $color-text-secondary;
  font-size: 12px;
}

.field-help {
  margin-top: 4px;
  color: $color-text-secondary;
  font-size: 12px;
}

.dialog-header {
  display: flex;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
  padding-right: 22px;
}

.dialog-header-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}

.script-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.hidden-file {
  display: none;
}

.advanced-row {
  display: flex;
  gap: 32px;
  align-items: center;
}

.advanced-item {
  display: flex;
  gap: 10px;
  align-items: center;
}

.advanced-label {
  color: $color-text-secondary;
  font-size: 13px;
}

.dialog-title {
  color: $color-text-primary;
  font-size: 15px;
}
</style>
