import request from './request'
import type { AlertQuery, AlertListResponse, AlertDetail, AggregationBucket, TimeRange } from '@/types'

export function getAlerts(params: AlertQuery): Promise<AlertListResponse> {
  return request.get('/alerts', { params })
}

export function getAlertDetail(id: string, index?: string): Promise<AlertDetail> {
  return request.get(`/alerts/${id}`, { params: index ? { index } : undefined })
}

export interface RuleContents {
  sid: number
  contents: string[]
  nocase: boolean
}

const MAX_RULE_CACHE = 300
const ruleContentsCache = new Map<number, Promise<RuleContents>>()

// 命中片段来自规则 content 字面量（Suricata 不记录命中偏移）
export function getRuleContents(sid: number): Promise<RuleContents> {
  if (!sid) return Promise.resolve({ sid: 0, contents: [], nocase: false })
  const cached = ruleContentsCache.get(sid)
  if (cached) return cached

  const task = request
    .get('/alerts/rule-contents', { params: { sid } })
    .then((res) => res as unknown as RuleContents)
  // 按 sid 缓存：同一条规则重复打开详情无需再请求；失败不缓存，下次仍可重试
  task.catch(() => ruleContentsCache.delete(sid))
  if (ruleContentsCache.size >= MAX_RULE_CACHE) {
    const oldest = ruleContentsCache.keys().next().value
    if (oldest !== undefined) ruleContentsCache.delete(oldest)
  }
  ruleContentsCache.set(sid, task)
  return task
}

/** 点击行即可按列表里的 sid 预取，与详情请求并行，省掉一次串行等待 */
export function prefetchRuleContents(sid?: number | null) {
  if (!sid) return
  getRuleContents(sid).catch(() => undefined)
}

export function getAlertAggregations(
  field: string,
  timeRange: TimeRange,
  timeFrom?: string,
  timeTo?: string,
): Promise<{ buckets: AggregationBucket[] }> {
  return request.get('/alerts/aggregations', {
    params: { field, time_range: timeRange, time_from: timeFrom, time_to: timeTo },
  })
}
