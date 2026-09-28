// 命中片段高亮：用于告警详情的 Payload / Response Body

const MAX_HIGHLIGHTS = 200

export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/**
 * 在原文中定位所有命中区间
 *
 * 用 indexOf 而非正则：规则字面量含大量正则元字符（. * [ ] | 等），
 * 不做转义也不会被解释为模式。
 */
export function findRanges(text: string, patterns: string[], ignoreCase = false): Array<[number, number]> {
  if (!text || !patterns.length) return []
  // 极少数字符 toLowerCase 后长度会变（如 'İ'），下标会错位 → 回退为大小写敏感
  const ci = ignoreCase && text.toLowerCase().length === text.length
  const haystack = ci ? text.toLowerCase() : text
  const ranges: Array<[number, number]> = []

  for (const pattern of patterns) {
    if (!pattern) continue
    const lower = pattern.toLowerCase()
    const needle = ci && lower.length === pattern.length ? lower : pattern
    let from = 0
    while (ranges.length < MAX_HIGHLIGHTS) {
      const at = haystack.indexOf(needle, from)
      if (at < 0) break
      ranges.push([at, at + needle.length])
      from = at + needle.length
    }
  }

  if (!ranges.length) return []
  ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1])

  // 合并重叠区间，避免嵌套 mark
  const merged: Array<[number, number]> = [ranges[0]]
  for (let i = 1; i < ranges.length; i++) {
    const last = merged[merged.length - 1]
    if (ranges[i][0] <= last[1]) {
      last[1] = Math.max(last[1], ranges[i][1])
    } else {
      merged.push([ranges[i][0], ranges[i][1]])
    }
  }
  return merged
}

/**
 * 渲染带高亮的 HTML
 *
 * 先取原文区间再分段转义拼接，而不是先转义再替换字符串：
 * 转义产生的实体（&amp; 等）会打断命中片段，且可能命中标签自身。
 */
export function renderHighlighted(text: string, patterns: string[], ignoreCase = false): string {
  if (!text) return ''
  const ranges = findRanges(text, patterns, ignoreCase)
  if (!ranges.length) return escapeHtml(text)

  let html = ''
  let cursor = 0
  for (const [start, end] of ranges) {
    if (start > cursor) html += escapeHtml(text.slice(cursor, start))
    html += `<mark class="hit">${escapeHtml(text.slice(start, end))}</mark>`
    cursor = end
  }
  if (cursor < text.length) html += escapeHtml(text.slice(cursor))
  return html
}
