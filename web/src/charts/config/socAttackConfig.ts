import type { EChartsOption } from 'echarts'
import { SOC_CATEGORY_COLORS } from '@/constants/esFieldMapping'

// SOC 攻击分类分布 - 横向堆叠条形图
export function buildSocAttackOption(
  data: Array<{ category: string; count: number }>,
): EChartsOption {
  const sorted = [...data].sort((a, b) => b.count - a.count)
  return {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (params: any) => {
        const p = params[0]
        const total = sorted.reduce((s, d) => s + d.count, 0)
        const pct = total > 0 ? ((p.value / total) * 100).toFixed(1) : '0'
        return `${p.name}<br/>数量: <b>${p.value}</b><br/>占比: ${pct}%`
      },
    },
    grid: { left: 100, right: 30, top: 16, bottom: 24, containLabel: false },
    xAxis: {
      type: 'value',
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: '#64748b', fontSize: 11 },
      splitLine: { lineStyle: { color: '#eef2f7' } },
    },
    yAxis: {
      type: 'category',
      data: sorted.map((d) => d.category),
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: '#475569', fontSize: 12 },
    },
    series: [
      {
        type: 'bar',
        data: sorted.map((d) => ({
          value: d.count,
          itemStyle: {
            color: SOC_CATEGORY_COLORS[d.category] || '#2563eb',
            borderRadius: [0, 4, 4, 0],
          },
        })),
        barWidth: 14,
        label: {
          show: true,
          position: 'right',
          color: '#475569',
          fontSize: 11,
          formatter: '{c}',
        },
      },
    ],
  }
}
