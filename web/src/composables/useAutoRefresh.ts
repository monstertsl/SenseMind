import { watch, onBeforeUnmount } from 'vue'
import { storeToRefs } from 'pinia'
import { useGlobalFilterStore } from '@/stores/globalFilter'
import type { RefreshInterval } from '@/types'

const INTERVAL_MS: Record<RefreshInterval, number | null> = {
  none: null,
  '5s': 5_000,
  '10s': 10_000,
  '30s': 30_000,
  '1m': 60_000,
  '2m': 120_000,
}

/**
 * 按 store.refreshInterval 自动周期调用 callback。
 * 只在监测中心与分析中心使用；refreshInterval === 'none' 时不启动定时器。
 */
export function useAutoRefresh(callback: () => void) {
  const { refreshInterval } = storeToRefs(useGlobalFilterStore())
  let timer: ReturnType<typeof setInterval> | null = null

  function clear() {
    if (timer) {
      clearInterval(timer)
      timer = null
    }
  }

  function setup() {
    clear()
    const ms = INTERVAL_MS[refreshInterval.value]
    if (ms) {
      timer = setInterval(callback, ms)
    }
  }

  watch(refreshInterval, setup, { immediate: true })
  onBeforeUnmount(clear)
}
