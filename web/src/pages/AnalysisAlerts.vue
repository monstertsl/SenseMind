<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import AlertSearchBar from '@/components/analysis/AlertSearchBar.vue'
import AlertTable from '@/components/analysis/AlertTable.vue'
import AlertDetailDrawer from '@/components/analysis/AlertDetailDrawer.vue'
import { useAlertList } from '@/composables/useAlertList'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import type { AlertQuery } from '@/types'

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

function handleSearch(filters: Partial<AlertQuery>) {
  // 应用搜索栏的筛选值到 query 对象
  query.source_ip = filters.source_ip
  query.destination_ip = filters.destination_ip
  query.soc_name = filters.soc_name
  query.alert_signature = filters.alert_signature
  query.attack_result = filters.attack_result
  query.page = 1
  fetch()
}

function handleReset() {
  query.source_ip = undefined
  query.destination_ip = undefined
  query.soc_name = undefined
  query.alert_signature = undefined
  query.attack_result = undefined
  query.source_alert_id = undefined
  query.page = 1
  fetch()
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

// 接收跨页面跳转带来的筛选
onMounted(() => {
  const pending = globalStore.consumePendingAlertFilter()
  const q = route.query
  // 优先消费 store 中的 pending filter（监测中心跳转）
  if (pending && Object.keys(pending).length) {
    applyFilter(pending)
  } else if (q.source_alert_id) {
    query.source_alert_id = q.source_alert_id as string
    fetch()
  } else {
    fetch()
  }
  fetchAggregations()
})
</script>

<template>
  <div class="analysis-alerts">
    <AlertSearchBar
      :model-value="query"
      :soc-name-buckets="socNameBuckets"
      @search="handleSearch"
      @reset="handleReset"
    />

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
