import { watch, onActivated, onDeactivated, onBeforeUnmount, type Ref } from 'vue'
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
 * 监测中心 / 分析中心 / 系统设置-设备管理使用；refreshInterval === 'none' 时不启动定时器。
 * enabled（可选）：联动开关，false 时暂停轮询（如 tab 切走时），恢复 true 重新拉起。
 */
export function useAutoRefresh(callback: () => void, enabled?: Ref<boolean>) {
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
    if (enabled && !enabled.value) return
    const ms = INTERVAL_MS[refreshInterval.value]
    if (ms) {
      timer = setInterval(callback, ms)
    }
  }

  const sources: Array<Ref<unknown>> = enabled ? [refreshInterval, enabled] : [refreshInterval]
  watch(sources, setup, { immediate: true })
  // keep-alive 缓存的页面：离开时暂停轮询、返回时恢复；未缓存的组件不触发这两个钩子
  onActivated(setup)
  onDeactivated(clear)
  onBeforeUnmount(clear)
}
