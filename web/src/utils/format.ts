import dayjs from 'dayjs'

// 时间格式化为 YYYY-MM-DD HH:mm:ss
export function formatDateTime(ts: string | null | undefined): string {
  if (!ts) return '-'
  const d = dayjs(ts)
  return d.isValid() ? d.format('YYYY-MM-DD HH:mm:ss') : '-'
}

// 时间格式化为 YYYY-MM-DD
export function formatDate(ts: string | null | undefined): string {
  if (!ts) return '-'
  const d = dayjs(ts)
  return d.isValid() ? d.format('YYYY-MM-DD') : '-'
}

// 端口：空值显示 -
export function formatPort(port: number | null | undefined): string {
  if (port === null || port === undefined || port === 0) return '-'
  return String(port)
}

// 通用空值
export function formatEmpty(val: unknown, placeholder = '-'): string {
  if (val === null || val === undefined || val === '') return placeholder
  return String(val)
}

// 可信度原值展示（无格式化）
export function formatConfidence(val: number | null | undefined): string {
  if (val === null || val === undefined) return '-'
  return String(val)
}

// 时间范围转 ES 查询区间
export function timeRangeToInterval(range: string): { from: string; to: string } {
  const to = dayjs()
  let from: dayjs.Dayjs
  switch (range) {
    case 'today':
      from = dayjs().startOf('day')
      break
    case 'yesterday':
      from = dayjs().subtract(1, 'day').startOf('day')
      const yesterdayEnd = dayjs().subtract(1, 'day').endOf('day')
      return { from: from.toISOString(), to: yesterdayEnd.toISOString() }
    case '7d':
      from = dayjs().subtract(7, 'day')
      break
    case '30d':
      from = dayjs().subtract(30, 'day')
      break
    default:
      from = dayjs().subtract(7, 'day')
  }
  return { from: from.toISOString(), to: to.toISOString() }
}

// 计算环比百分比
export function calcChangeRate(current: number, previous: number): number {
  if (previous === 0) return current > 0 ? 100 : 0
  return ((current - previous) / previous) * 100
}

// 复制到剪贴板
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    // fallback
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    try {
      document.execCommand('copy')
      return true
    } catch {
      return false
    } finally {
      document.body.removeChild(ta)
    }
  }
}
