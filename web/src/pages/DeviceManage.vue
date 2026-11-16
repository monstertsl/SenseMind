<!-- 设备管理页（F16）：探针全生命周期管理——列表 / 添加探针 / 编辑备注 / 吊销 / 手动删除 -->
<template>
  <div class="device-manage">
    <div class="toolbar">
      <el-button type="primary" :icon="Plus" @click="openAddDialog">添加探针</el-button>
      <el-button :icon="Refresh" @click="load">刷新</el-button>
    </div>

    <el-table :data="probes" v-loading="loading" class="probe-table">
      <el-table-column label="备注名" min-width="140">
        <template #default="{ row }">
          <span class="probe-name">{{ row.name || '-' }}</span>
        </template>
      </el-table-column>
      <el-table-column label="站点" min-width="100">
        <template #default="{ row }">{{ row.site || '-' }}</template>
      </el-table-column>
      <el-table-column label="内部 ID" min-width="150">
        <template #default="{ row }">
          <span class="font-mono">{{ row.probe_uid }}</span>
        </template>
      </el-table-column>
      <el-table-column label="状态" min-width="110">
        <template #default="{ row }">
          <el-tag :type="statusTagType(row)" size="small">{{ statusText(row) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="最近上报" min-width="160">
        <template #default="{ row }">
          <span class="font-mono">{{ formatTime(row.last_report_at) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="健康状态" min-width="190">
        <template #default="{ row }">
          <template v-if="row.online && row.health">
            <div class="health-cells">
              <span class="health-cell" :class="healthLevel(row.health.cpu)">
                CPU {{ fmtPct(row.health.cpu) }}</span>
              <span class="health-cell" :class="healthLevel(row.health.mem)">
                内存 {{ fmtPct(row.health.mem) }}</span>
              <span class="health-cell" :class="healthLevel(row.health.disk)">
                磁盘 {{ fmtPct(row.health.disk) }}</span>
            </div>
            <el-tooltip placement="top">
              <template #content>
                <div>下行 {{ fmtBps(row.health.rx_bps) }} / 上行 {{ fmtBps(row.health.tx_bps) }}</div>
                <div>丢包率 {{ row.health.drop_pct != null ? row.health.drop_pct + '%' : '-' }}</div>
              </template>
              <span class="health-detail-hint">流量/丢包</span>
            </el-tooltip>
          </template>
          <span v-else class="health-none">-</span>
        </template>
      </el-table-column>
      <el-table-column label="证书到期" min-width="160">
        <template #default="{ row }">
          <span class="font-mono">{{ formatTime(row.cert_not_after) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="注册 IP" min-width="130">
        <template #default="{ row }">
          <span class="font-mono">{{ row.registered_ip || '-' }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="200" fixed="right">
        <template #default="{ row }">
          <div class="action-buttons">
            <el-button text size="small" :icon="Edit" :disabled="row.status === 'pending'"
              @click="openEditDialog(row)">编辑</el-button>
            <el-button text size="small" type="warning" :disabled="row.status === 'revoked'"
              @click="handleRevoke(row)">吊销</el-button>
            <el-button text size="small" type="danger" @click="handleDelete(row)">删除</el-button>
          </div>
        </template>
      </el-table-column>
    </el-table>

    <!-- 添加探针（生成一次性 token） -->
    <el-dialog v-model="addVisible" title="添加探针" width="520px" destroy-on-close class="device-dialog">
      <el-form label-width="90px" label-position="left">
        <el-form-item label="备注名">
          <el-input v-model="addForm.name" maxlength="100" placeholder="如 总部-边界1（必填）" />
        </el-form-item>
        <el-form-item label="站点">
          <el-input v-model="addForm.site" maxlength="100" placeholder="如 总部机房（可选）" />
        </el-form-item>
        <el-form-item label="重装覆盖">
          <div class="rebind-row">
            <el-switch v-model="addForm.isRebind" />
            <el-select v-if="addForm.isRebind" v-model="addForm.rebind_uid" placeholder="选择要重装的探针"
              class="rebind-select">
              <el-option v-for="p in rebindable" :key="p.probe_uid"
                :label="`${p.name || p.probe_uid}（${p.probe_uid}）`" :value="p.probe_uid" />
            </el-select>
          </div>
          <div class="field-help">重装场景：IP 未变时绑定原内部 ID 覆盖签发，旧证书自动标记吊销</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="addVisible = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="handleCreateToken">生成 token</el-button>
      </template>
    </el-dialog>

    <!-- token 一次性展示 -->
    <el-dialog v-model="tokenVisible" title="接入 token 已生成" width="560px" :close-on-click-modal="false" class="device-dialog">
      <el-alert type="warning" :closable="false" class="token-warn"
        title="token 仅此一次展示，关闭后无法再查看" description="请立即复制并随部署包交给装机人员；token 24 小时内有效、仅可使用一次。" />
      <div class="token-field">
        <div class="token-label">内部 ID</div>
        <div class="font-mono token-value">{{ tokenResult?.probe_uid }}</div>
      </div>
      <div class="token-field">
        <div class="token-label">token</div>
        <div class="token-row">
          <span class="font-mono token-value">{{ tokenResult?.token }}</span>
          <el-button size="small" type="primary" @click="copyToken">复制</el-button>
        </div>
      </div>
      <div class="token-field">
        <div class="token-label">有效期至</div>
        <div class="font-mono token-value">{{ formatTime(tokenResult?.expires_at || null) }}</div>
      </div>
      <template #footer>
        <el-button type="primary" @click="tokenVisible = false">我已保存</el-button>
      </template>
    </el-dialog>

    <!-- 编辑备注 -->
    <el-dialog v-model="editVisible" title="编辑探针备注" width="460px" destroy-on-close class="device-dialog">
      <el-form label-width="90px" label-position="left">
        <el-form-item label="内部 ID">
          <span class="font-mono">{{ editForm.probe_uid }}</span>
        </el-form-item>
        <el-form-item label="备注名">
          <el-input v-model="editForm.name" maxlength="100" />
        </el-form-item>
        <el-form-item label="站点">
          <el-input v-model="editForm.site" maxlength="100" />
        </el-form-item>
      </el-form>
      <div class="field-help">备注仅用于界面展示，修改不影响历史数据</div>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="handleSaveEdit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh, Edit } from '@element-plus/icons-vue'
import {
  listProbes, createProbeToken, updateProbe, revokeProbe, deleteProbe,
  type ProbeItem, type ProbeTokenResult,
} from '@/api/probes'

const probes = ref<ProbeItem[]>([])
const loading = ref(false)
let refreshTimer: ReturnType<typeof setInterval> | null = null

// ---- 列表 ----
async function load() {
  loading.value = true
  try {
    probes.value = await listProbes()
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  refreshTimer = setInterval(load, 30_000)
})
onBeforeUnmount(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})

// ---- 状态展示 ----
function statusTagType(row: ProbeItem) {
  if (row.status === 'active') return row.online ? 'success' : 'info'
  if (row.status === 'pending') return 'warning'
  return 'danger'
}

function statusText(row: ProbeItem) {
  if (row.status === 'active') return row.online ? '在线' : '离线'
  if (row.status === 'pending') return row.token_state ? `待接入（${row.token_state}）` : '待接入'
  return '已吊销'
}

function formatTime(t: string | null): string {
  if (!t) return '-'
  try {
    return new Date(t).toLocaleString('zh-CN', { hour12: false })
  } catch {
    return t
  }
}

// ---- 健康展示（F7）----
function fmtPct(v: number | null | undefined): string {
  return v == null ? '-' : `${v}%`
}

function fmtBps(v: number | null | undefined): string {
  if (v == null) return '-'
  if (v >= 1048576) return `${(v / 1048576).toFixed(1)} MB/s`
  if (v >= 1024) return `${(v / 1024).toFixed(1)} KB/s`
  return `${v} B/s`
}

// CPU/内存/磁盘健康分级：<70 正常 / <90 关注 / >=90 告警
function healthLevel(v: number | null | undefined): string {
  if (v == null) return ''
  if (v >= 90) return 'health-danger'
  if (v >= 70) return 'health-warn'
  return 'health-ok'
}

// ---- 添加探针 ----
const addVisible = ref(false)
const creating = ref(false)
const addForm = reactive({ name: '', site: '', isRebind: false, rebind_uid: '' })
const rebindable = computed(() => probes.value.filter((p) => p.status === 'active'))

function openAddDialog() {
  addForm.name = ''
  addForm.site = ''
  addForm.isRebind = false
  addForm.rebind_uid = ''
  addVisible.value = true
}

const tokenVisible = ref(false)
const tokenResult = ref<ProbeTokenResult | null>(null)

async function handleCreateToken() {
  if (!addForm.name.trim()) {
    ElMessage.warning('请填写备注名')
    return
  }
  if (addForm.isRebind && !addForm.rebind_uid) {
    ElMessage.warning('重装覆盖需要选择要重装的探针')
    return
  }
  creating.value = true
  try {
    tokenResult.value = await createProbeToken({
      name: addForm.name.trim(),
      site: addForm.site.trim(),
      rebind_uid: addForm.isRebind ? addForm.rebind_uid : undefined,
    })
    addVisible.value = false
    tokenVisible.value = true
    load()
  } finally {
    creating.value = false
  }
}

async function copyToken() {
  if (!tokenResult.value) return
  try {
    await navigator.clipboard.writeText(tokenResult.value.token)
    ElMessage.success('token 已复制')
  } catch {
    ElMessage.warning('复制失败，请手动选择复制')
  }
}

// ---- 编辑备注 ----
const editVisible = ref(false)
const saving = ref(false)
const editForm = reactive({ probe_uid: '', name: '', site: '' })

function openEditDialog(row: ProbeItem) {
  editForm.probe_uid = row.probe_uid
  editForm.name = row.name
  editForm.site = row.site
  editVisible.value = true
}

async function handleSaveEdit() {
  saving.value = true
  try {
    await updateProbe(editForm.probe_uid, { name: editForm.name.trim(), site: editForm.site.trim() })
    ElMessage.success('备注已更新')
    editVisible.value = false
    load()
  } finally {
    saving.value = false
  }
}

// ---- 吊销 / 删除 ----
async function handleRevoke(row: ProbeItem) {
  await ElMessageBox.confirm(
    `确认吊销探针「${row.name || row.probe_uid}」？吊销后续签被拒绝，探针拉取配置后将自我停服，注册表条目保留。`,
    '吊销确认',
    { confirmButtonText: '吊销', cancelButtonText: '取消', type: 'warning' },
  )
  await revokeProbe(row.probe_uid)
  ElMessage.success('已吊销')
  load()
}

async function handleDelete(row: ProbeItem) {
  await ElMessageBox.confirm(
    `确认从注册表中彻底删除「${row.name || row.probe_uid}」？历史事件数据不受影响，但该内部 ID 将无法继续续签管理。`,
    '删除确认',
    { confirmButtonText: '删除', cancelButtonText: '取消', type: 'error' },
  )
  await deleteProbe(row.probe_uid)
  ElMessage.success('已删除')
  load()
}
</script>

<style scoped lang="scss">
.device-manage {
  padding: 6px 0 2px;
}

.health-cells {
  display: flex;
  gap: 6px;
  align-items: center;
}

.health-cell {
  font-family: $font-mono;
  font-feature-settings: 'tnum';
  font-size: 12px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 3px;
}

.health-ok {
  color: $color-success;
  background: rgba($color-success, 0.08);
}

.health-warn {
  color: $color-warning;
  background: rgba($color-warning, 0.08);
}

.health-danger {
  color: $color-danger;
  background: rgba($color-danger, 0.08);
}

.health-detail-hint {
  font-size: 11px;
  color: $color-text-secondary;
  cursor: default;
  border-bottom: 1px dashed currentColor;
}

.health-none {
  color: $color-text-secondary;
}

.toolbar {
  display: flex;
  gap: 10px;
  margin-bottom: 12px;
}

.probe-name {
  font-weight: 600;
  color: $color-text-primary;
}

.action-buttons {
  display: flex;
  gap: 2px;

  :deep(.el-button) {
    margin-left: 0;
  }
}

.rebind-row {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;

  .rebind-select {
    flex: 1;
  }
}

.field-help {
  font-size: 12px;
  color: $color-text-secondary;
  width: 100%;
  margin-top: 4px;
}

.token-warn {
  margin-bottom: 14px;
}

.token-field {
  margin-bottom: 12px;

  .token-label {
    font-size: 12px;
    color: $color-text-secondary;
    margin-bottom: 4px;
  }

  .token-value {
    font-size: 14px;
    font-weight: 600;
    color: $color-text-primary;
    word-break: break-all;
  }

  .token-row {
    display: flex;
    align-items: center;
    gap: 10px;

    .token-value {
      flex: 1;
      background: $color-bg-soft;
      border: 1px solid $color-border;
      border-radius: $radius-md;
      padding: 8px 10px;
    }
  }
}
</style>

<!-- 非 scoped：el-dialog teleport 到 body，需全局样式（与用户管理/LLM 弹窗同款规范：
     等宽字体 + 标题 700 / 标签与输入 600 分级加粗，中文经 mono 栈回退到 HarmonyOS Sans） -->
<style lang="scss">
.device-dialog {
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

  .el-input__inner,
  .el-select__placeholder,
  .el-select__selected-item {
    font-family: $font-mono;
    font-feature-settings: 'tnum';
    font-weight: 600;
  }

  .el-switch__label {
    font-family: $font-mono;
    font-feature-settings: 'tnum';
    font-weight: 600;
  }
}
</style>
