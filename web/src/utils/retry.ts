/**
 * 自动重试工具：后端不可用时静默重试，不抛错、不弹窗
 * - 失败后延迟 retryInterval ms 自动重试，直到成功
 * - 调用方保持 loading=true 直到成功，页面持续显示加载动画
 * - 返回 clear 函数，用于在重新触发或组件卸载时清除待重试定时器
 */
export function createAutoRetry(
  fn: () => Promise<void>,
  retryInterval = 3000,
): { run: () => void; clear: () => void } {
  let timer: ReturnType<typeof setTimeout> | null = null
  let disposed = false

  function clear() {
    if (timer) {
      clearTimeout(timer)
      timer = null
    }
  }

  async function run() {
    if (disposed) return
    clear()
    try {
      await fn()
    } catch {
      if (disposed) return
      // 静默失败，延迟后自动重试
      timer = setTimeout(run, retryInterval)
    }
  }

  return {
    run,
    clear,
  }
}
