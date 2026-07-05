<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import LogConditionBuilder from '@/components/log/LogConditionBuilder.vue'
import LogList from '@/components/log/LogList.vue'
import LogDetailDrawer from '@/components/log/LogDetailDrawer.vue'
import { useLogSearch } from '@/composables/useLogSearch'
import { useLogExplorerStore } from '@/stores/logExplorer'
import { useCrossPageRouter } from '@/composables/useCrossPageRouter'
import { getLogDetail } from '@/api/logs'
import type { LogItem } from '@/types'

const route = useRoute()
const store = useLogExplorerStore()
const {
  list,
  total,
  loading,
  req,
  fetch,
  loadMapping,
} = useLogSearch()
const { goToAnalysisFromLog } = useCrossPageRouter()

const drawerVisible = ref(false)
const selectedLog = ref<LogItem | null>(null)
const detailLoading = ref(false)

function handleSearch() {
  req.page = 1
  fetch()
}

function handleReset() {
  store.clearConditions()
  req.page = 1
  fetch()
}

function handlePageChange(page: number) {
  req.page = page
  fetch()
}

function handleSizeChange(size: number) {
  req.page_size = size
  req.page = 1
  fetch()
}

async function handleRowClick(row: LogItem) {
  selectedLog.value = row
  drawerVisible.value = true
  detailLoading.value = true
  try {
    const detail = await getLogDetail(row._id, row._index)
    selectedLog.value = { ...row, _source: detail }
  } catch {
    // 保留列表中的 _source
  } finally {
    detailLoading.value = false
  }
}

function handleAiClick(row: LogItem) {
  goToAnalysisFromLog(row.ai_doc_id, row._source?.ai?.source_alert_id)
}

function handleViewAi() {
  if (selectedLog.value) handleAiClick(selectedLog.value)
}

// 接收跨页面跳转：分析中心原始日志ID（即 _id）→ 自动生成条件行查 soc-* 索引
onMounted(() => {
  loadMapping()
  const pendingId = store.consumePendingSourceAlertId()
  const qId = route.query.source_alert_id as string | undefined
  const id = pendingId || qId
  if (id) {
    store.clearConditions()
    store.addCondition('_id', 'eq', id)
    fetch()
  }
  // 默认不加载日志，仅在检索或跨页面跳转时加载
})
</script>

<template>
  <div class="log-explorer">
    <LogConditionBuilder @search="handleSearch" @reset="handleReset" />

    <div class="list-section" v-loading="loading && !list.length">
      <div class="list-toolbar">
        <span class="result-count">
          共 <b class="font-mono">{{ total }}</b> 条日志
        </span>
      </div>

      <LogList
        :data="list"
        :loading="loading"
        @row-click="handleRowClick"
        @ai-click="handleAiClick"
      />

      <div class="pagination-wrap">
        <el-pagination
          :current-page="req.page"
          :page-size="req.page_size"
          :total="total"
          :page-sizes="[20, 50, 100, 200]"
          layout="total, sizes, prev, pager, next, jumper"
          background
          @current-change="handlePageChange"
          @size-change="handleSizeChange"
        />
      </div>
    </div>

    <LogDetailDrawer
      v-model="drawerVisible"
      :log="selectedLog"
      :loading="detailLoading"
      @view-ai="handleViewAi"
      @analyzed="fetch"
    />
  </div>
</template>

<style scoped lang="scss">
.log-explorer {
  display: flex;
  flex-direction: column;
  gap: $space-lg;
}

.list-section {
  background: $color-bg-elevated;
  border-radius: $radius-lg;
  border: 1px solid $color-border-light;
  overflow: hidden;
}

.list-toolbar {
  padding: $space-md $space-xl;
  border-bottom: 1px solid $color-divider;
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
