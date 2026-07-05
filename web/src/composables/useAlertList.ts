import { ref, reactive, watch, onBeforeUnmount } from 'vue'
import { storeToRefs } from 'pinia'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import { getAlerts, getAlertDetail, getAlertAggregations } from '@/api/alerts'
import { createAutoRetry } from '@/utils/retry'
import type { AlertItem, AlertDetail, AlertQuery, AggregationBucket, TimeRange } from '@/types'

export function useAlertList() {
  const globalStore = useGlobalFilterStore()
  const { timeRange } = storeToRefs(globalStore)

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
      const res = await getAlertAggregations('ai.soc_name', timeRange.value)
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
