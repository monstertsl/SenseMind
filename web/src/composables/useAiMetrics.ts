import { ref, watch, onBeforeUnmount } from 'vue'
import { storeToRefs } from 'pinia'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import { getMetricsOverview } from '@/api/metrics'
import { createAutoRetry } from '@/utils/retry'
import type { MetricsOverview } from '@/types'

export function useAiMetrics() {
  const globalStore = useGlobalFilterStore()
  const { timeRange } = storeToRefs(globalStore)

  const data = ref<MetricsOverview | null>(null)
  const loading = ref(false)

  const retry = createAutoRetry(async () => {
    const res = await getMetricsOverview(timeRange.value)
    data.value = res
    loading.value = false
  })

  function fetch() {
    loading.value = true
    retry.run()
  }

  watch(timeRange, fetch, { immediate: true })

  onBeforeUnmount(() => {
    retry.clear()
  })

  return { data, loading, fetch }
}
