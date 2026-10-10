<script setup lang="ts">
import { computed, onActivated, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import AlertSearchBar from '@/components/analysis/AlertSearchBar.vue'
import AlertPresetBar from '@/components/analysis/AlertPresetBar.vue'
import AlertTable from '@/components/analysis/AlertTable.vue'
import AlertDetailDrawer from '@/components/analysis/AlertDetailDrawer.vue'
import { useAlertList } from '@/composables/useAlertList'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import { ALERT_FILTER_KEYS, pickAlertFilters } from '@/constants/alertFilters'
import type { AlertQuery } from '@/types'

// 组件名用于 MainLayout 的 keep-alive include 匹配
defineOptions({ name: 'AnalysisAlerts' })

const route = useRoute()
const globalStore = useGlobalFilterStore()
const {
  list,
  total,
  loading,
  query,
  socNameBuckets,
  detail,
  detailLoading,
  fetch,
  fetchAggregations,
  fetchDetail,
  applyFilter,
} = useAlertList()

const drawerVisible = ref(false)
const selectedRowId = ref<string>('')

// 按全局刷新间隔自动拉取告警列表
useAutoRefresh(fetch)

// 当前检索条件（供快捷检索保存）
const currentFilters = computed(() => pickAlertFilters(query))

function clearFilters() {
  const raw = query as unknown as Record<string, unknown>
  for (const key of ALERT_FILTER_KEYS) raw[key] = undefined
}

/** 应用一组筛选条件（整体替换），搜索栏与检索快捷方式共用 */
function handleSearch(filters: Partial<AlertQuery>) {
  clearFilters()
  const raw = query as unknown as Record<string, unknown>
  for (const key of ALERT_FILTER_KEYS) {
    const value = (filters as Record<string, unknown>)[key]
    if (value !== undefined && value !== null && value !== '') raw[key] = value
  }
  query.page = 1
  fetch()
}

function handleReset() {
  clearFilters()
  query.source_alert_id = undefined
  query.page = 1
  fetch()
}

// 保存检索入口在搜索栏按钮组，弹窗与数据由快捷检索栏管理
const presetBarRef = ref<{ openSaveDialog: () => void } | null>(null)

function handleSavePreset() {
  presetBarRef.value?.openSaveDialog()
}

function handleSort(field: string, order: 'asc' | 'desc') {
  query.sort_field = field
  query.sort_order = order
  fetch()
}

function handlePageChange(page: number) {
  query.page = page
  fetch()
}

function handleSizeChange(size: number) {
  query.page_size = size
  query.page = 1
  fetch()
}

function handleRowClick(row: any) {
  selectedRowId.value = row._id
  drawerVisible.value = true
  fetchDetail(row._id)
}

function handleIpClick(ip: string) {
  if (!ip) return
  ;(query as any).source_ip = ip
  query.page = 1
  fetch()
}

// 已处理过的跳转日志ID，避免复活时重复应用同一 query
let handledAlertId = ''

// 进入页面时决定是否拉取：只有真正消费到跨页面跳转的筛选条件、或当前无数据时才请求，
// 其余情况复用已有数据，避免每次从其他页面切回都重新加载
function ensureLoaded() {
  const pending = globalStore.consumePendingAlertFilter()
  // 优先消费 store 中的 pending filter（监测中心跳转）
  if (pending && Object.keys(pending).length) {
    handledAlertId = ''
    applyFilter(pending)
    fetchAggregations()
    return
  }
  const alertId = (route.query.source_alert_id as string) || ''
  if (alertId && alertId !== handledAlertId) {
    handledAlertId = alertId
    query.source_alert_id = alertId
    query.page = 1
    fetch()
    fetchAggregations()
    return
  }
  // loading 中说明请求已在进行（首次挂载时 onMounted 与 onActivated 会先后触发）
  if (!list.value.length && !loading.value) {
    fetch()
    fetchAggregations()
  }
}

onMounted(ensureLoaded)
onActivated(ensureLoaded)
</script>

<template>
  <div class="analysis-alerts">
    <AlertSearchBar
      :model-value="query"
      :soc-name-buckets="socNameBuckets"
      @search="handleSearch"
      @reset="handleReset"
      @save="handleSavePreset"
    />

    <!-- 快捷检索：检索栏下方独立一行 -->
    <AlertPresetBar ref="presetBarRef" :filters="currentFilters" @apply="handleSearch" />

    <div class="table-section" v-loading="loading && !list.length">
      <div class="table-toolbar">
        <span class="result-count">
          共 <b class="font-mono">{{ total }}</b> 条告警
        </span>
      </div>
      <AlertTable
        :data="list"
        :loading="loading"
        :page="query.page"
        :page-size="query.page_size"
        @sort="handleSort"
        @row-click="handleRowClick"
        @ip-click="handleIpClick"
      />
      <div class="pagination-wrap">
        <el-pagination
          :current-page="query.page"
          :page-size="query.page_size"
          :total="total"
          :page-sizes="[20, 50, 100, 200]"
          layout="total, sizes, prev, pager, next, jumper"
          background
          @current-change="handlePageChange"
          @size-change="handleSizeChange"
        />
      </div>
    </div>

    <AlertDetailDrawer
      v-model="drawerVisible"
      :detail="detail"
      :loading="detailLoading"
    />
  </div>
</template>

<style scoped lang="scss">
.analysis-alerts {
  display: flex;
  flex-direction: column;
  gap: $space-lg;
}

.table-section {
  background: $color-bg-elevated;
  border-radius: $radius-lg;
  border: 1px solid $color-border-light;
  overflow: hidden;
}

.table-toolbar {
  padding: $space-md $space-xl;
  border-bottom: 1px solid $color-divider;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.result-count {
  font-size: 13px;
  color: $color-text-secondary;
  b {
    color: $color-primary;
    font-weight: 700;
  }
}

.pagination-wrap {
  padding: $space-md $space-xl;
  display: flex;
  justify-content: flex-end;
  border-top: 1px solid $color-divider;
}
</style>
