import { ref, reactive, watch, onBeforeUnmount } from 'vue'
import { storeToRefs } from 'pinia'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import { getAlerts, getAlertDetail, getAlertAggregations } from '@/api/alerts'
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
    const res = await getAlerts(query)
    list.value = res.items
    total.value = res.total
    loading.value = false
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
    query.source_ip = undefined
    query.destination_ip = undefined
    query.soc_name = undefined
    query.source_alert_id = undefined
    query.exclude_source_ip = undefined
    query.exclude_destination_ip = undefined
    query.exclude_alert_signature = undefined
    for (const [k, v] of Object.entries(filter)) {
      if (k === 'source_ip') query.source_ip = v as string
      else if (k === 'destination_ip') query.destination_ip = v as string
      else if (k === 'soc_name') query.soc_name = v as string
      else if (k === 'source_alert_id') query.source_alert_id = v as string
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
