import { defineStore } from 'pinia'
import { ref, watch } from 'vue'
import type { TimeRange, CustomTimeRange, RefreshInterval } from '@/types'

const STORAGE_KEYS = {
  timeRange: 'sensemind_timeRange',
  customTime: 'sensemind_customTime',
  refreshInterval: 'sensemind_refreshInterval',
}

function loadStored<T>(key: string, fallback: T): T {
  const raw = localStorage.getItem(key)
  if (raw === null) return fallback
  try {
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

// 全局筛选状态：时间粒度 + 跨页面搜索条件 + 刷新间隔（localStorage 持久化）
export const useGlobalFilterStore = defineStore('globalFilter', () => {
  const timeRange = ref<TimeRange>(loadStored(STORAGE_KEYS.timeRange, 'today'))
  const customTime = ref<CustomTimeRange>(loadStored(STORAGE_KEYS.customTime, { start: '', end: '' }))
  const refreshInterval = ref<RefreshInterval>(loadStored(STORAGE_KEYS.refreshInterval, 'none'))
  const mappingValid = ref<boolean | null>(null) // null=未校验
  const missingFields = ref<string[]>([])

  // 跨页面跳转携带的筛选（监测中心→分析中心）
  const pendingAlertFilter = ref<Record<string, string | string[]> | null>(null)

  watch(timeRange, (v) => localStorage.setItem(STORAGE_KEYS.timeRange, JSON.stringify(v)))
  watch(customTime, (v) => localStorage.setItem(STORAGE_KEYS.customTime, JSON.stringify(v)), { deep: true })
  watch(refreshInterval, (v) => localStorage.setItem(STORAGE_KEYS.refreshInterval, JSON.stringify(v)))

  function setTimeRange(range: TimeRange) {
    timeRange.value = range
  }

  function setCustomTime(start: string, end: string) {
    customTime.value = { start, end }
  }

  function setRefreshInterval(interval: RefreshInterval) {
    refreshInterval.value = interval
  }

  function setMappingValidation(valid: boolean, missing: string[]) {
    mappingValid.value = valid
    missingFields.value = missing
  }

  function setPendingAlertFilter(filter: Record<string, string | string[]> | null) {
    pendingAlertFilter.value = filter
  }

  function consumePendingAlertFilter(): Record<string, string | string[]> | null {
    const f = pendingAlertFilter.value
    pendingAlertFilter.value = null
    return f
  }

  return {
    timeRange,
    customTime,
    refreshInterval,
    mappingValid,
    missingFields,
    pendingAlertFilter,
    setTimeRange,
    setCustomTime,
    setRefreshInterval,
    setMappingValidation,
    setPendingAlertFilter,
    consumePendingAlertFilter,
  }
})
