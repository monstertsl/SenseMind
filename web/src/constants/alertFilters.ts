// 分析中心筛选条件集中管理 —— 筛选键名与后端 AlertQueryParams 对齐
// 这些键同时构成「检索快捷方式」保存的 filters 结构，后续告警联动直接复用
// 禁止在组件内硬编码筛选键名

import type { AlertQuery } from '@/types'

/** 可保存 / 可清空的筛选键（不含时间范围、分页与排序） */
export const ALERT_FILTER_KEYS = [
  'source_ip',
  'destination_ip',
  'soc_name',
  'threat_verdict',
  'attack_result',
  'alert_signature',
  'kql',
  'confidence',
  'confidence_min',
  'confidence_max',
  'exclude_source_ip',
  'exclude_destination_ip',
  'exclude_alert_signature',
] as const

export type AlertFilterKey = (typeof ALERT_FILTER_KEYS)[number]

/** 筛选键的中文标签（用于快捷方式条件摘要展示） */
export const ALERT_FILTER_LABELS: Record<AlertFilterKey, string> = {
  source_ip: '源IP',
  destination_ip: '目的IP',
  soc_name: '告警类型',
  threat_verdict: '威胁判定',
  attack_result: '攻击结果',
  alert_signature: '威胁名',
  kql: 'KQL',
  confidence: '可信度',
  confidence_min: '可信度≥',
  confidence_max: '可信度≤',
  exclude_source_ip: '排除源IP',
  exclude_destination_ip: '排除目的IP',
  exclude_alert_signature: '排除威胁名',
}

/** 威胁判定选项（取值与 ai.threat_verdict 一致） */
export const THREAT_VERDICT_OPTIONS = [
  { label: '确认威胁', value: '确认威胁' },
  { label: '可疑', value: '可疑' },
  { label: '误报', value: '误报' },
]

/** 攻击结果选项（取值与 ai.attack_result 一致） */
export const ATTACK_RESULT_OPTIONS = [
  { label: '成功', value: '成功' },
  { label: '失败', value: '失败' },
  { label: '未知', value: '未知' },
]

// 排除前缀：英文 ! 与中文 ！ 均支持
const EXCLUDE_PREFIXES = ['!', '！']

/** 解析排除输入：返回是否排除及去掉前缀后的值 */
export function parseExcludeInput(raw: string): { exclude: boolean; value: string } {
  const text = (raw || '').trim()
  for (const prefix of EXCLUDE_PREFIXES) {
    if (text.startsWith(prefix)) {
      return { exclude: true, value: text.slice(prefix.length).trim() }
    }
  }
  return { exclude: false, value: text }
}

/** 提取查询对象里的筛选条件（用于保存为快捷方式） */
export function pickAlertFilters(source: Partial<AlertQuery>): Partial<AlertQuery> {
  const filters: Record<string, unknown> = {}
  for (const key of ALERT_FILTER_KEYS) {
    const value = (source as Record<string, unknown>)[key]
    if (value !== undefined && value !== null && value !== '') filters[key] = value
  }
  return filters as Partial<AlertQuery>
}

/** 把筛选条件转成可读摘要，如「威胁判定=确认威胁，可信度≥=0.8」 */
export function describeAlertFilters(filters: Partial<AlertQuery>): string {
  const parts: string[] = []
  for (const key of ALERT_FILTER_KEYS) {
    const value = (filters as Record<string, unknown>)[key]
    if (value === undefined || value === null || value === '') continue
    const text = Array.isArray(value) ? value.join('/') : String(value)
    parts.push(`${ALERT_FILTER_LABELS[key]}=${text}`)
  }
  return parts.join('，')
}
