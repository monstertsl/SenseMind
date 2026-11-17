<!-- 设备管理页（F16）：探针全生命周期管理——列表 / 添加探针 / 编辑设备 / 吊销 / 手动删除 -->
<template>
  <div class="device-manage">
    <div class="toolbar">
      <el-button type="primary" :icon="Plus" @click="openAddDialog">添加探针</el-button>
      <el-button :icon="Refresh" :class="{ 'refresh-loading': loading }" @click="load">刷新</el-button>
    </div>

    <SkeletonTable v-if="loading" :rows="5" :columns="9" />
    <el-table v-else :data="probes" class="probe-table">
      <el-table-column label="设备名称" min-width="140">
        <template #default="{ row }">
          <span class="probe-name">{{ row.name || '-' }}</span>
        </template>
      </el-table-column>
      <el-table-column label="站点" min-width="100">
        <template #default="{ row }">{{ row.site || '-' }}</template>
      </el-table-column>
      <el-table-column label="设备ID" min-width="150">
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
      <el-table-column label="健康状态" min-width="120">
        <template #default="{ row }">
          <template v-if="row.online && row.health">
            <el-tooltip placement="top">
              <template #content>
                <div>CPU {{ fmtPct(row.health.cpu) }} / 内存 {{ fmtPct(row.health.mem) }} / 磁盘 {{ fmtPct(row.health.disk) }}</div>
                <!-- 收发拆分/丢包率是旧心跳协议字段，新 agent 时序上报不产出，只显示真实存在的总流量 -->
                <div>流量 {{ fmtMbps(row.health.traffic_mbps) }}</div>
                <div>点击查看资源趋势详情</div>
              </template>
              <el-tag :type="healthTagType(row)" size="small" class="health-tag" @click="openHealthDetail(row)">
                {{ healthLabel(row) }}
              </el-tag>
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
        <el-form-item label="设备名称">
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
          <div class="field-help">重装场景：IP 未变时绑定原设备ID 覆盖签发，旧证书自动标记吊销</div>
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
        <div class="token-label">设备ID</div>
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

    <!-- 编辑设备 -->
    <el-dialog v-model="editVisible" title="编辑设备" width="460px" destroy-on-close class="device-dialog">
      <el-form label-width="90px" label-position="left">
        <el-form-item label="设备ID">
          <span class="font-mono">{{ editForm.probe_uid }}</span>
        </el-form-item>
        <el-form-item label="设备名称">
          <el-input v-model="editForm.name" maxlength="100" />
        </el-form-item>
        <el-form-item label="站点">
          <el-input v-model="editForm.site" maxlength="100" />
        </el-form-item>
      </el-form>
      <div class="field-help">设备名称仅用于界面展示，修改不影响历史数据</div>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="handleSaveEdit">保存</el-button>
      </template>
    </el-dialog>

    <!-- 健康详情：复用监测中心资源趋势图（探针时序） -->
    <el-dialog v-model="healthVisible" title="设备健康详情" width="1100px" destroy-on-close class="device-dialog">
      <div class="health-detail-head">
        <span class="hd-name">{{ healthDetail?.name || '-' }}</span>
        <span class="hd-uid font-mono">{{ healthDetail?.probe_uid }}</span>
      </div>
      <div class="range-switch">
        <button
          v-for="r in METRIC_RANGES"
          :key="r.value"
          class="range-btn"
          :class="{ active: healthRange === r.value }"
          @click="healthRange = r.value"
        >
          {{ r.label }}
        </button>
      </div>
      <div class="trend-grid">
        <ResourceTrendChart :range="healthRange" :probe-id="healthDetail?.probe_uid" />
        <TrafficTrendChart :range="healthRange" :probe-id="healthDetail?.probe_uid" />
        <DiskGaugeCard
          :probe-id="healthDetail?.probe_uid"
          :disk-used="healthDetail?.health?.disk_used ?? null"
          :disk-total="healthDetail?.health?.disk_total ?? null"
        />
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh, Edit } from '@element-plus/icons-vue'
import SkeletonTable from '@/components/common/SkeletonTable.vue'
import ResourceTrendChart from '@/components/monitor/ResourceTrendChart.vue'
import TrafficTrendChart from '@/components/monitor/TrafficTrendChart.vue'
import DiskGaugeCard from '@/components/monitor/DiskGaugeCard.vue'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import type { MetricRange } from '@/types'
import {
  listProbes, createProbeToken, updateProbe, revokeProbe, deleteProbe,
  type ProbeItem, type ProbeTokenResult,
} from '@/api/probes'

const props = defineProps<{ active?: boolean }>()

const probes = ref<ProbeItem[]>([])
const loading = ref(false)

// ---- 列表 ----
// 最小转圈时长：接口太快时仍保证刷新图标至少旋转一圈，肉眼可见
const MIN_SPIN_MS = 600
let firstLoad = true // 首屏加载由骨架屏反馈，刷新按钮不转
async function load() {
  loading.value = true
  const start = Date.now()
  try {
    probes.value = await listProbes()
  } finally {
    // 首次加载（挂载）不保证最小时长，按钮不转；后续手动/自动刷新保证至少转一圈
    const remain = firstLoad ? 0 : MIN_SPIN_MS - (Date.now() - start)
    firstLoad = false
    if (remain > 0) {
      setTimeout(() => { loading.value = false }, remain)
    } else {
      loading.value = false
    }
  }
}

onMounted(load)
// 自动刷新跟随右上角全局刷新间隔（none/5s/10s/30s/1m/2m），仅在本 tab 可见时轮询
useAutoRefresh(load, computed(() => props.active !== false))

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

function fmtMbps(v: number | null | undefined): string {
  return v == null ? '-' : `${v} Mbps`
}

// 综合健康分级：取 CPU/内存/磁盘 的最高档——任一 >=90 告警 / 任一 >=70 关注 / 其余健康
type HealthLevel = 'alert' | 'watch' | 'ok'

function healthScore(row: ProbeItem): HealthLevel {
  const h = row.health
  const vals = [h?.cpu ?? 0, h?.mem ?? 0, h?.disk ?? 0]
  if (vals.some((v) => v >= 90)) return 'alert'
  if (vals.some((v) => v >= 70)) return 'watch'
  return 'ok'
}

function healthTagType(row: ProbeItem): 'danger' | 'warning' | 'success' {
  const s = healthScore(row)
  return s === 'alert' ? 'danger' : s === 'watch' ? 'warning' : 'success'
}

function healthLabel(row: ProbeItem): string {
  const s = healthScore(row)
  return s === 'alert' ? '告警' : s === 'watch' ? '关注' : '健康'
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
    ElMessage.warning('请填写设备名称')
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

// ---- 编辑设备 ----
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
    ElMessage.success('设备信息已更新')
    editVisible.value = false
    load()
  } finally {
    saving.value = false
  }
}

// ---- 健康详情弹窗（复用监测中心资源趋势图）----
const healthVisible = ref(false)
const healthDetail = ref<ProbeItem | null>(null)
const healthRange = ref<MetricRange>('1h')
const METRIC_RANGES: Array<{ label: string; value: MetricRange }> = [
  { label: '最近1小时', value: '1h' },
  { label: '最近24小时', value: '24h' },
  { label: '最近7天', value: '7d' },
]

function openHealthDetail(row: ProbeItem) {
  healthDetail.value = row
  healthRange.value = '1h'
  healthVisible.value = true
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
    `确认从注册表中彻底删除「${row.name || row.probe_uid}」？历史事件数据不受影响，但该设备ID 将无法继续续签管理。`,
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

// 综合健康标签：可点击查看趋势详情
.health-tag {
  cursor: pointer;
}

// 健康详情弹窗头部：设备名称 + 设备ID
.health-detail-head {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin-bottom: 10px;

  .hd-name {
    font-size: 16px;
    font-weight: 700;
    color: $color-text-primary;
  }

  .hd-uid {
    font-size: 12px;
    color: $color-text-secondary;
  }
}

// 时间档位切换（与监测中心资源趋势区同款样式）
.range-switch {
  display: flex;
  gap: 4px;
  background: $color-bg-soft;
  padding: 3px;
  border-radius: 6px;
  margin-bottom: 14px;
  width: fit-content;
}

.range-btn {
  border: none;
  background: transparent;
  color: $color-text-secondary;
  font-size: 12px;
  padding: 4px 12px;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;

  &:hover {
    color: $color-text-regular;
  }

  &.active {
    background: #fff;
    color: $color-primary;
    font-weight: 600;
    box-shadow: $shadow-sm;
  }
}

// 三个趋势图布局（与监测中心一致）
.trend-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
  align-items: stretch;
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
