import { ref, reactive, onBeforeUnmount } from 'vue'
import { storeToRefs } from 'pinia'
import { useLogExplorerStore } from '@/stores/logExplorer'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import { searchLogs, getLogMapping } from '@/api/logs'
import { createAutoRetry } from '@/utils/retry'
import type { LogItem, LogSearchRequest } from '@/types'

export function useLogSearch() {
  const store = useLogExplorerStore()
  const { conditions, kqlMode, kqlText, keyword, fieldMappings } = storeToRefs(store)
  const globalStore = useGlobalFilterStore()

  const list = ref<LogItem[]>([])
  const total = ref(0)
  const loading = ref(false)

  const req = reactive<LogSearchRequest>({
    conditions: [],
    kql: '',
    indices: ['soc-*', 'soc-ai-*'],
    time_range: 'today',
    page: 1,
    page_size: 20,
    sort_field: '@timestamp',
    sort_order: 'desc',
  })

  function syncTimeRange() {
    if (globalStore.timeRange === 'custom') {
      req.time_range = 'custom'
      req.time_from = globalStore.customTime.start || undefined
      req.time_to = globalStore.customTime.end || undefined
    } else {
      req.time_range = globalStore.timeRange
      req.time_from = undefined
      req.time_to = undefined
    }
  }

  const retry = createAutoRetry(async () => {
    syncTimeRange()
    req.conditions = conditions.value as any
    req.kql = kqlMode.value ? kqlText.value : undefined
    req.keyword = keyword.value.trim() || undefined
    const res = await searchLogs(req)
    list.value = res.items
    total.value = res.total
    loading.value = false
  })

  function fetch() {
    loading.value = true
    retry.run()
  }

  async function loadMapping() {
    try {
      const res = await getLogMapping(req.indices)
      store.setFieldMappings(res.fields)
    } catch {
      // 静默失败：字段下拉框降级使用本地 ai.* 字段定义
    }
  }

  function resetPage() {
    req.page = 1
  }

  onBeforeUnmount(() => {
    retry.clear()
  })

  return {
    list,
    total,
    loading,
    req,
    conditions,
    kqlMode,
    kqlText,
    keyword,
    fieldMappings,
    fetch,
    loadMapping,
    resetPage,
  }
}
