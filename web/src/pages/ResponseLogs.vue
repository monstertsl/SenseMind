<script setup lang="ts">
// 联动日志：记录设备联动的每一次处置，成功/失败都留痕（失败带设备报错）
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh, Search } from '@element-plus/icons-vue'
import {
  listResponseRecordDevices,
  listResponseRecords,
  revokeResponseRecord,
  type ResponseRecordAction,
  type ResponseRecordItem,
  type ResponseRecordStatus,
} from '@/api/responseAction'
import SkeletonTable from '@/components/common/SkeletonTable.vue'
import { formatDateTime } from '@/utils/format'

const loading = ref(false)
const records = ref<ResponseRecordItem[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const devices = ref<{ id: number; name: string }[]>([])

const filters = reactive({
  ip: '',
  action: '' as '' | ResponseRecordAction,
  status: '' as '' | ResponseRecordStatus,
  deviceId: null as number | null,
})

function errorText(error: unknown, fallback: string): string {
  const detail = (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail
  return detail || (error as Error)?.message || fallback
}

async function load() {
  loading.value = true
  try {
    const data = await listResponseRecords({
      ip: filters.ip.trim() || undefined,
      action: filters.action || undefined,
      status: filters.status || undefined,
      device_id: filters.deviceId || undefined,
      page: page.value,
      page_size: pageSize.value,
    })
    records.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    ElMessage.error(errorText(error, '联动日志加载失败'))
  } finally {
    loading.value = false
  }
}

async function loadDevices() {
  try {
    const data = await listResponseRecordDevices()
    devices.value = data.items || []
  } catch {
    devices.value = []
  }
}

function search() {
  page.value = 1
  load()
}

function reset() {
  filters.ip = ''
  filters.action = ''
  filters.status = ''
  filters.deviceId = null
  search()
}

function onPageChange(value: number) {
  page.value = value
  load()
}

// 撤销：只对「封堵成功」的记录开放，解封结果另记一条日志
const revokingId = ref<number | null>(null)

async function revoke(row: ResponseRecordItem) {
  try {
    await ElMessageBox.confirm(`确认撤销对 ${row.ip} 的封堵？`, '撤销封堵', {
      type: 'warning',
      confirmButtonText: '撤销',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  revokingId.value = row.id
  try {
    const result = await revokeResponseRecord(row.id)
    if (result.status === 'success') ElMessage.success(`已撤销 ${row.ip} 的封堵`)
    else ElMessage.error(`撤销失败：${result.error_message || '设备未返回原因'}`)
    load()
  } catch (error) {
    ElMessage.error(errorText(error, '撤销失败'))
  } finally {
    revokingId.value = null
  }
}

onMounted(() => {
  loadDevices()
  load()
})
</script>

<template>
  <div class="logs-page">
    <section class="section-block">
      <div class="block-title-row">
        <div class="block-title">联动日志</div>
        <div class="row-actions">
          <el-button :icon="Refresh" @click="load">刷新</el-button>
        </div>
      </div>

      <div class="filter-row">
        <el-input
          v-model="filters.ip"
          class="filter-ip"
          placeholder="处置地址，支持模糊匹配"
          clearable
          @keyup.enter="search"
          @clear="search"
        />
        <el-select v-model="filters.action" class="filter-action" placeholder="动作" @change="search">
          <el-option label="全部动作" value="" />
          <el-option label="封堵" value="block" />
          <el-option label="解封" value="unblock" />
        </el-select>
        <el-select v-model="filters.status" class="filter-status" placeholder="处置结果" @change="search">
          <el-option label="全部结果" value="" />
          <el-option label="成功" value="success" />
          <el-option label="失败" value="failed" />
        </el-select>
        <el-select
          v-model="filters.deviceId"
          class="filter-device"
          placeholder="联动设备"
          clearable
          @change="search"
        >
          <el-option v-for="item in devices" :key="item.id" :label="item.name" :value="item.id" />
        </el-select>
        <div class="filter-actions">
          <el-button type="primary" :icon="Search" @click="search">查询</el-button>
          <el-button @click="reset">重置</el-button>
        </div>
      </div>

      <SkeletonTable v-if="loading" :rows="5" :columns="6" />
      <template v-else>
        <el-table :data="records" row-key="id" class="logs-table">
          <el-table-column label="时间" width="180">
            <template #default="scope">{{ formatDateTime(scope.row.created_at) }}</template>
          </el-table-column>
          <el-table-column label="处置地址" min-width="160">
            <template #default="scope">
              <span class="font-mono">{{ scope.row.ip }}</span>
            </template>
          </el-table-column>
          <el-table-column label="动作" width="80">
            <template #default="scope">
              {{ scope.row.action === 'unblock' ? '解封' : '封堵' }}
            </template>
          </el-table-column>
          <el-table-column label="处置结果" width="100">
            <template #default="scope">
              <el-tag :type="scope.row.status === 'success' ? 'success' : 'danger'" size="small">
                {{ scope.row.status === 'success' ? '成功' : '失败' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="device_name" label="联动设备" min-width="140" />
          <el-table-column prop="task_name" label="触发方式" min-width="140">
            <template #default="scope">{{ scope.row.task_name || '—' }}</template>
          </el-table-column>
          <el-table-column label="失败原因" min-width="220" show-overflow-tooltip>
            <template #default="scope">
              <span :class="{ 'error-text': scope.row.status === 'failed' }">
                {{ scope.row.error_message || '—' }}
              </span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="84" align="center">
            <template #default="scope">
              <el-button
                v-if="scope.row.action === 'block' && scope.row.status === 'success'"
                link
                type="primary"
                :loading="revokingId === scope.row.id"
                @click="revoke(scope.row)"
              >撤销</el-button>
              <span v-else class="muted-text">—</span>
            </template>
          </el-table-column>
        </el-table>

        <div v-if="!records.length" class="empty-tip">暂无联动日志</div>
        <div v-if="total > pageSize" class="pager-row">
          <el-pagination
            :current-page="page"
            :page-size="pageSize"
            :total="total"
            layout="total, prev, pager, next"
            background
            @current-change="onPageChange"
          />
        </div>
      </template>
    </section>
  </div>
</template>

<style scoped lang="scss">
.logs-page {
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

.filter-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
  padding-top: 12px;
  border-top: 1px solid $color-border;
}

.filter-ip {
  width: 240px;
}

.filter-action {
  width: 120px;
}

.filter-status {
  width: 130px;
}

.filter-device {
  width: 180px;
}

.filter-actions {
  display: flex;
  gap: 8px;
  margin-left: auto;
}

.logs-table {
  width: 100%;
}

.font-mono {
  font-family: $font-mono;
}

.error-text {
  color: $color-danger;
}

.muted-text {
  color: $color-text-secondary;
}

.empty-tip {
  padding: 28px 12px;
  color: $color-text-secondary;
  font-size: 13px;
  text-align: center;
}

.pager-row {
  display: flex;
  justify-content: flex-end;
  padding-top: 4px;
}

@media (max-width: 700px) {
  .section-block {
    padding: 16px;
  }

  .filter-ip,
  .filter-action,
  .filter-status,
  .filter-device {
    width: 100%;
  }

  .filter-actions {
    width: 100%;
    margin-left: 0;
  }
}
</style>
