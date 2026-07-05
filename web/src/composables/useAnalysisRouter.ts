import { useRouter } from 'vue-router'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import type { TimeRange } from '@/types'

// 分析中心跳转工具：统一处理跨页面参数传递
export function useAnalysisRouter() {
  const router = useRouter()
  const globalStore = useGlobalFilterStore()

  // 跳转分析中心并带入筛选条件
  function goToAnalysis(filter: Record<string, string | string[]> = {}, timeRange?: TimeRange) {
    if (timeRange) globalStore.setTimeRange(timeRange)
    globalStore.setPendingAlertFilter(filter)
    router.push({
      path: '/analysis/alerts',
      query: buildQuery(filter),
    })
  }

  // 监测中心卡片跳转映射
  function goFromMetricCard(cardKey: string, timeRange: TimeRange) {
    const filterMap: Record<string, Record<string, string>> = {
      total_alerts: {}, // 仅时间筛选
      victim_assets: { sort: 'destination_ip' },
      attacker_count: { sort: 'source_ip' },
    }
    const filter = filterMap[cardKey] || {}
    goToAnalysis(filter, timeRange)
  }

  // 图表元素跳转
  function goFromChart(field: string, value: string, timeRange: TimeRange) {
    goToAnalysis({ [field]: value }, timeRange)
  }

  function buildQuery(filter: Record<string, string | string[]>): Record<string, string> {
    const q: Record<string, string> = {}
    for (const [k, v] of Object.entries(filter)) {
      q[k] = Array.isArray(v) ? v.join(',') : v
    }
    return q
  }

  return { goToAnalysis, goFromMetricCard, goFromChart }
}
