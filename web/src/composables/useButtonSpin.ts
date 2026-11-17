import { ref } from 'vue'

/**
 * 按钮 loading 旋转动画（刷新/重置按钮通用）。
 * 接口响应太快时 loading 状态一闪而过，这里保证图标至少旋转 minMs（约一圈），
 * 页面自己的 loading 为 true 时会覆盖延长。
 */
const MIN_SPIN_MS = 600

export function useButtonSpin() {
  const spinning = ref(false)
  let timer: ReturnType<typeof setTimeout> | null = null

  function spin(minMs: number = MIN_SPIN_MS) {
    spinning.value = true
    if (timer) clearTimeout(timer)
    timer = setTimeout(() => { spinning.value = false }, minMs)
  }

  return { spinning, spin }
}
