import { ref, reactive, watch, onBeforeUnmount } from 'vue'
import { ElMessage } from 'element-plus'
import { storeToRefs } from 'pinia'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import { getAlerts, getAlertDetail, getAlertAggregations } from '@/api/alerts'
import { ALERT_FILTER_KEYS } from '@/constants/alertFilters'
import { createAutoRetry } from '@/utils/retry'
import type { AlertItem, AlertDetail, AlertQuery, AggregationBucket, TimeRange } from '@/types'

export function useAlertList() {
  const globalStore = useGlobalFilterStore()
  const { timeRange, customTime } = storeToRefs(globalStore)

  const list = ref<AlertItem[]>([])
  const total = ref(0)
  const loading = ref(false)

  const query = reactive<AlertQuery>({
    time_range: 'today',
    page: 1,
    page_size: 20,
    sort_field: 'ai.alert_timestamp',
    sort_order: 'desc',
  })

  const socNameBuckets = ref<AggregationBucket[]>([])

  function syncTimeRange() {
    query.time_range = timeRange.value as TimeRange
    // 自定义时间范围：把起止时间传给后端
    if (timeRange.value === 'custom' && customTime.value.start && customTime.value.end) {
      query.time_from = customTime.value.start
      query.time_to = customTime.value.end
    } else {
      query.time_from = undefined
      query.time_to = undefined
    }
  }

  const retry = createAutoRetry(async () => {
    syncTimeRange()
    try {
      const res = await getAlerts(query)
      list.value = res.items
      total.value = res.total
      loading.value = false
    } catch (e: any) {
      // 4xx 属参数问题（如 KQL 语法错误）：重试无意义，停止重试并提示
      const status = e?.response?.status
      if (typeof status === 'number' && status >= 400 && status < 500) {
        list.value = []
        total.value = 0
        loading.value = false
        ElMessage.error(e?.response?.data?.detail || '查询失败，请检查检索条件')
        return
      }
      throw e
    }
  })

  function fetch() {
    loading.value = true
    retry.run()
  }

  async function fetchAggregations() {
    try {
      const isCustom = timeRange.value === 'custom'
      const res = await getAlertAggregations(
        'ai.soc_name',
        timeRange.value,
        isCustom ? customTime.value.start || undefined : undefined,
        isCustom ? customTime.value.end || undefined : undefined,
      )
      socNameBuckets.value = res.buckets
    } catch {
      // 静默失败
    }
  }

  // 详情抽屉
  const detail = ref<AlertDetail | null>(null)
  const detailLoading = ref(false)

  async function fetchDetail(id: string) {
    detailLoading.value = true
    try {
      detail.value = await getAlertDetail(id)
      // 从列表中查找该告警的 alert_count（前端连续聚合时已计算）
      const item = list.value.find((i) => i._id === id)
      if (item?.ai?.alert_count && detail.value?.ai) {
        detail.value.ai.alert_count = item.ai.alert_count
      } else if (detail.value?.ai) {
        detail.value.ai.alert_count = 1
      }
    } catch {
      detail.value = null
    } finally {
      detailLoading.value = false
    }
  }

  function applyFilter(filter: Record<string, string | string[]>) {
    const raw = query as unknown as Record<string, unknown>
    for (const key of ALERT_FILTER_KEYS) raw[key] = undefined
    query.source_alert_id = undefined
    for (const [k, v] of Object.entries(filter)) {
      const known = k === 'source_alert_id' || (ALERT_FILTER_KEYS as readonly string[]).includes(k)
      if (known) raw[k] = Array.isArray(v) ? v.join(',') : v
    }
    query.page = 1
    fetch()
  }

  watch(timeRange, () => {
    query.page = 1
    fetch()
    fetchAggregations()
  })

  // 自定义时间范围确认后，若当前已是 custom 粒度则立即刷新
  watch(
    customTime,
    () => {
      if (timeRange.value === 'custom') {
        query.page = 1
        fetch()
        fetchAggregations()
      }
    },
    { deep: true },
  )

  onBeforeUnmount(() => {
    retry.clear()
  })

  return {
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
  }
}
