<script setup lang="ts">
import { ref, reactive, onMounted, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh, Delete, Edit } from '@element-plus/icons-vue'
import {
  listBypassRules, createBypassRule, updateBypassRule, deleteBypassRule,
  type BypassRuleItem,
} from '@/api/bypassRule'

const rules = ref<BypassRuleItem[]>([])
const loading = ref(false)
const keyword = ref('')
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)

async function fetchRules() {
  loading.value = true
  try {
    const params: Record<string, unknown> = {
      page: page.value,
      page_size: pageSize.value,
    }
    if (keyword.value.trim()) params.keyword = keyword.value.trim()
    const data = await listBypassRules(params as any)
    rules.value = data.items
    total.value = data.total
  } catch (e: any) {
    ElMessage.error(e?.message || '加载白名单失败')
    rules.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  page.value = 1
  fetchRules()
}

function handlePageChange(p: number) {
  page.value = p
  fetchRules()
}

function handleSizeChange() {
  page.value = 1
  fetchRules()
}

onMounted(fetchRules)

// ---- IP / 端口校验 ----
function validateIp(ip: string): boolean {
  if (!ip) return true
  if (ip.includes('/')) return false
  const parts = ip.split('.')
  if (parts.length !== 4) return false
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255)
}

function validatePort(port: string): boolean {
  if (!port) return true
  const n = Number(port)
  return /^\d+$/.test(port) && n >= 1 && n <= 65535
}

// 域名标签：每段 [a-z0-9] 开头结尾，中间可含 -；TLD 至少 2 个字母
const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/
function normalizeHost(raw: string): string {
  let h = (raw || '').trim().toLowerCase()
  if (h.startsWith('*.')) h = h.slice(2)
  if (h.includes('://')) h = h.split('://', 1)[1]
  h = h.split('/', 1)[0]
  h = h.split(':', 1)[0]
  return h.replace(/\.+$/, '')
}
function validateHost(host: string): boolean {
  if (!host) return true
  return HOST_RE.test(normalizeHost(host))
}

// ---- 新建白名单 ----
const createDialogVisible = ref(false)
const createForm = reactive({
  src_ip: '',
  src_port: '',
  dst_ip: '',
  dst_port: '',
  host: '',
  remark: '',
})
const createErrors = reactive({
  src_ip: '',
  src_port: '',
  dst_ip: '',
  dst_port: '',
  host: '',
})

function openCreateDialog() {
  Object.assign(createForm, { src_ip: '', src_port: '', dst_ip: '', dst_port: '', host: '', remark: '' })
  Object.assign(createErrors, { src_ip: '', src_port: '', dst_ip: '', dst_port: '', host: '' })
  createDialogVisible.value = true
}

function validateCreateForm(): boolean {
  Object.assign(createErrors, { src_ip: '', src_port: '', dst_ip: '', dst_port: '', host: '' })
  let ok = true
  if (createForm.src_ip && !validateIp(createForm.src_ip)) {
    createErrors.src_ip = '请输入正确的 IP 地址（不支持子网）'
    ok = false
  }
  if (createForm.src_port && !validatePort(createForm.src_port)) {
    createErrors.src_port = '端口范围 1-65535'
    ok = false
  }
  if (createForm.dst_ip && !validateIp(createForm.dst_ip)) {
    createErrors.dst_ip = '请输入正确的 IP 地址（不支持子网）'
    ok = false
  }
  if (createForm.dst_port && !validatePort(createForm.dst_port)) {
    createErrors.dst_port = '端口范围 1-65535'
    ok = false
  }
  if (createForm.host && !validateHost(createForm.host)) {
    createErrors.host = '请输入正确的域名（如 example.com）'
    ok = false
  }
  // 全空校验
  if (!createForm.src_ip && !createForm.src_port && !createForm.dst_ip && !createForm.dst_port && !createForm.host) {
    ElMessage.warning('至少填写一个四元组字段或 Host')
    return false
  }
  return ok
}

async function handleCreate() {
  if (!validateCreateForm()) return
  try {
    await createBypassRule({
      src_ip: createForm.src_ip,
      src_port: createForm.src_port ? parseInt(createForm.src_port) : 0,
      dst_ip: createForm.dst_ip,
      dst_port: createForm.dst_port ? parseInt(createForm.dst_port) : 0,
      host: createForm.host,
      remark: createForm.remark,
    } as any)
    ElMessage.success('白名单规则已创建')
    createDialogVisible.value = false
    fetchRules()
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '创建失败')
  }
}

// ---- 编辑白名单 ----
const editDialogVisible = ref(false)
const editForm = ref<{
  id: number
  src_ip: string
  src_port: string
  dst_ip: string
  dst_port: string
  host: string
  remark: string
} | null>(null)
const editErrors = reactive({
  src_ip: '',
  src_port: '',
  dst_ip: '',
  dst_port: '',
  host: '',
})

// ---- 实时校验（输入时即提示）----
watch(() => createForm.src_ip, (v) => {
  createErrors.src_ip = (v && !validateIp(v)) ? '请输入正确的 IP 地址（不支持子网）' : ''
})
watch(() => createForm.src_port, (v) => {
  createErrors.src_port = (v && !validatePort(v)) ? '端口范围 1-65535' : ''
})
watch(() => createForm.dst_ip, (v) => {
  createErrors.dst_ip = (v && !validateIp(v)) ? '请输入正确的 IP 地址（不支持子网）' : ''
})
watch(() => createForm.dst_port, (v) => {
  createErrors.dst_port = (v && !validatePort(v)) ? '端口范围 1-65535' : ''
})
watch(() => createForm.host, (v) => {
  createErrors.host = (v && !validateHost(v)) ? '请输入正确的域名（如 example.com）' : ''
})
watch(() => editForm.value?.src_ip, (v) => {
  editErrors.src_ip = (v && !validateIp(v)) ? '请输入正确的 IP 地址（不支持子网）' : ''
})
watch(() => editForm.value?.src_port, (v) => {
  editErrors.src_port = (v && !validatePort(v)) ? '端口范围 1-65535' : ''
})
watch(() => editForm.value?.dst_ip, (v) => {
  editErrors.dst_ip = (v && !validateIp(v)) ? '请输入正确的 IP 地址（不支持子网）' : ''
})
watch(() => editForm.value?.dst_port, (v) => {
  editErrors.dst_port = (v && !validatePort(v)) ? '端口范围 1-65535' : ''
})
watch(() => editForm.value?.host, (v) => {
  editErrors.host = (v && !validateHost(v)) ? '请输入正确的域名（如 example.com）' : ''
})

function openEditDialog(row: BypassRuleItem) {
  editForm.value = {
    id: row.id,
    src_ip: row.src_ip,
    src_port: row.src_port ? String(row.src_port) : '',
    dst_ip: row.dst_ip,
    dst_port: row.dst_port ? String(row.dst_port) : '',
    host: row.host,
    remark: row.remark,
  }
  Object.assign(editErrors, { src_ip: '', src_port: '', dst_ip: '', dst_port: '', host: '' })
  editDialogVisible.value = true
}

function validateEditForm(): boolean {
  if (!editForm.value) return false
  Object.assign(editErrors, { src_ip: '', src_port: '', dst_ip: '', dst_port: '', host: '' })
  let ok = true
  if (editForm.value.src_ip && !validateIp(editForm.value.src_ip)) {
    editErrors.src_ip = '请输入正确的 IP 地址（不支持子网）'
    ok = false
  }
  if (editForm.value.src_port && !validatePort(editForm.value.src_port)) {
    editErrors.src_port = '端口范围 1-65535'
    ok = false
  }
  if (editForm.value.dst_ip && !validateIp(editForm.value.dst_ip)) {
    editErrors.dst_ip = '请输入正确的 IP 地址（不支持子网）'
    ok = false
  }
  if (editForm.value.dst_port && !validatePort(editForm.value.dst_port)) {
    editErrors.dst_port = '端口范围 1-65535'
    ok = false
  }
  if (editForm.value.host && !validateHost(editForm.value.host)) {
    editErrors.host = '请输入正确的域名（如 example.com）'
    ok = false
  }
  if (!editForm.value.src_ip && !editForm.value.src_port && !editForm.value.dst_ip && !editForm.value.dst_port && !editForm.value.host) {
    ElMessage.warning('至少保留一个四元组字段或 Host')
    return false
  }
  return ok
}

async function handleEdit() {
  if (!editForm.value || !validateEditForm()) return
  try {
    await updateBypassRule(editForm.value.id, {
      src_ip: editForm.value.src_ip,
      src_port: editForm.value.src_port ? parseInt(editForm.value.src_port) : 0,
      dst_ip: editForm.value.dst_ip,
      dst_port: editForm.value.dst_port ? parseInt(editForm.value.dst_port) : 0,
      host: editForm.value.host,
      remark: editForm.value.remark,
    } as any)
    ElMessage.success('白名单规则已更新')
    editDialogVisible.value = false
    fetchRules()
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '更新失败')
  }
}

// ---- 删除白名单 ----
async function handleDelete(row: BypassRuleItem) {
  try {
    await ElMessageBox.confirm('确认删除该白名单规则吗？', '危险操作', {
      type: 'error', confirmButtonText: '删除', confirmButtonClass: 'el-button--danger',
    })
    await deleteBypassRule(row.id)
    ElMessage.success('已删除')
    fetchRules()
  } catch (e: any) {
    if (e === 'cancel') return
    ElMessage.error(e?.response?.data?.detail || e?.message || '删除失败')
  }
}

function formatPort(port: number | string): string {
  const n = typeof port === 'string' ? port : (port ? String(port) : '')
  return n || '*'
}

function formatIp(ip: string): string {
  return ip || '*'
}

function formatHost(host: string): string {
  return host || '*'
}

function formatTime(t: string | null): string {
  if (!t) return '-'
  try {
    return new Date(t).toLocaleString('zh-CN', { hour12: false })
  } catch {
    return t
  }
}
</script>

<template>
  <div class="bypass-manage">
    <div class="toolbar">
      <div class="toolbar-left">
        <el-input
          v-model="keyword"
          placeholder="按 IP / Host / 备注搜索"
          clearable
          class="search-input"
          @keyup.enter="handleSearch"
        />
        <el-button :icon="Refresh" @click="fetchRules">刷新</el-button>
      </div>
      <el-button type="primary" :icon="Plus" @click="openCreateDialog">新建白名单</el-button>
    </div>

    <el-table v-loading="loading" :data="rules" stripe class="rule-table">
      <el-table-column label="源 IP" min-width="140">
        <template #default="{ row }">
          <span class="font-mono">{{ formatIp(row.src_ip) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="源端口" min-width="90">
        <template #default="{ row }">
          <span class="font-mono">{{ formatPort(row.src_port) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="目的 IP" min-width="140">
        <template #default="{ row }">
          <span class="font-mono">{{ formatIp(row.dst_ip) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="目的端口" min-width="90">
        <template #default="{ row }">
          <span class="font-mono">{{ formatPort(row.dst_port) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="Host" min-width="160" show-overflow-tooltip>
        <template #default="{ row }">
          <span class="font-mono">{{ formatHost(row.host) }}</span>
        </template>
      </el-table-column>
      <el-table-column prop="remark" label="备注" min-width="140" show-overflow-tooltip />
      <el-table-column label="创建时间" min-width="170">
        <template #default="{ row }">
          <span class="font-mono">{{ formatTime(row.created_at) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="更新时间" min-width="170">
        <template #default="{ row }">
          <span class="font-mono">{{ formatTime(row.updated_at) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="170" fixed="right">
        <template #default="{ row }">
          <div class="action-buttons">
            <el-button text size="small" :icon="Edit" @click="openEditDialog(row)">编辑</el-button>
            <el-button text size="small" type="danger" :icon="Delete" @click="handleDelete(row)">删除</el-button>
          </div>
        </template>
      </el-table-column>
    </el-table>

    <div class="pagination">
      <el-pagination
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :total="total"
        :page-sizes="[20, 50, 100, 200]"
        layout="total, sizes, prev, pager, next, jumper"
        background
        @current-change="handlePageChange"
        @size-change="handleSizeChange"
      />
    </div>

    <!-- 新建白名单 -->
    <el-dialog v-model="createDialogVisible" title="新建白名单" width="480px" class="bypass-create-dialog">
      <el-form label-width="90px" label-position="left">
        <el-form-item label="源 IP">
          <el-input v-model="createForm.src_ip" placeholder="留空表示任意" />
          <div v-if="createErrors.src_ip" class="field-error">{{ createErrors.src_ip }}</div>
        </el-form-item>
        <el-form-item label="源端口">
          <el-input v-model="createForm.src_port" placeholder="留空表示任意" />
          <div v-if="createErrors.src_port" class="field-error">{{ createErrors.src_port }}</div>
        </el-form-item>
        <el-form-item label="目的 IP">
          <el-input v-model="createForm.dst_ip" placeholder="留空表示任意" />
          <div v-if="createErrors.dst_ip" class="field-error">{{ createErrors.dst_ip }}</div>
        </el-form-item>
        <el-form-item label="目的端口">
          <el-input v-model="createForm.dst_port" placeholder="留空表示任意" />
          <div v-if="createErrors.dst_port" class="field-error">{{ createErrors.dst_port }}</div>
        </el-form-item>
        <el-form-item label="Host">
          <el-input v-model="createForm.host" placeholder="域名，如 example.com（匹配该域名及所有子域名，忽略端口）" />
          <div v-if="createErrors.host" class="field-error">{{ createErrors.host }}</div>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="createForm.remark" placeholder="如：LLM API 流量" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleCreate">创建</el-button>
      </template>
    </el-dialog>

    <!-- 编辑白名单 -->
    <el-dialog v-model="editDialogVisible" title="编辑白名单" width="480px" class="bypass-edit-dialog">
      <el-form v-if="editForm" label-width="90px" label-position="left">
        <el-form-item label="源 IP">
          <el-input v-model="editForm.src_ip" placeholder="留空表示任意" />
          <div v-if="editErrors.src_ip" class="field-error">{{ editErrors.src_ip }}</div>
        </el-form-item>
        <el-form-item label="源端口">
          <el-input v-model="editForm.src_port" placeholder="留空表示任意" />
          <div v-if="editErrors.src_port" class="field-error">{{ editErrors.src_port }}</div>
        </el-form-item>
        <el-form-item label="目的 IP">
          <el-input v-model="editForm.dst_ip" placeholder="留空表示任意" />
          <div v-if="editErrors.dst_ip" class="field-error">{{ editErrors.dst_ip }}</div>
        </el-form-item>
        <el-form-item label="目的端口">
          <el-input v-model="editForm.dst_port" placeholder="留空表示任意" />
          <div v-if="editErrors.dst_port" class="field-error">{{ editErrors.dst_port }}</div>
        </el-form-item>
        <el-form-item label="Host">
          <el-input v-model="editForm.host" placeholder="域名，如 example.com（匹配该域名及所有子域名，忽略端口）" />
          <div v-if="editErrors.host" class="field-error">{{ editErrors.host }}</div>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="editForm.remark" placeholder="如：LLM API 流量" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleEdit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped lang="scss">
.bypass-manage {
  padding: 4px 0;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;

  .toolbar-left {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .search-input {
    width: 240px;
  }
}

.rule-table {
  width: 100%;

  :deep(.el-table__cell) {
    padding: 10px 0;
  }

  :deep(.el-table__header .cell) {
    font-size: 14px;
    font-weight: 700;
    color: $color-primary;
    padding: 0 12px;
  }

  :deep(.el-table__body .cell) {
    font-size: 14px;
    font-weight: 600;
    font-family: $font-mono;
    font-feature-settings: 'tnum';
    padding: 0 12px;
  }

  :deep(.el-button) {
    font-weight: 600;
  }
}

.action-buttons {
  display: flex;
  gap: 4px;
  white-space: nowrap;
}

.pagination {
  display: flex;
  justify-content: flex-end;
  padding-top: 4px;
  margin-top: auto;
}

.field-error {
  margin-top: 4px;
  font-size: 12px;
  font-weight: 600;
  font-family: $font-mono;
  color: #e6a23c;
}
</style>

<!-- 非 scoped：el-dialog teleport 到 body，需全局样式 -->
<style lang="scss">
.bypass-edit-dialog,
.bypass-create-dialog {
  .el-dialog__title {
    font-family: $font-mono;
    font-feature-settings: 'tnum';
    font-weight: 700;
  }

  .el-form-item__label {
    font-family: $font-mono;
    font-feature-settings: 'tnum';
    font-weight: 600;
  }

  .el-input__inner {
    font-family: $font-mono;
    font-feature-settings: 'tnum';
    font-weight: 600;
  }
}
</style>
