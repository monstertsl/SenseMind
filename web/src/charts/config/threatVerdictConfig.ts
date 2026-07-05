import type { EChartsOption } from 'echarts'

// 威胁判定分布 - 环形图（可靠/可疑/不可信）
export function buildThreatVerdictOption(data: {
  reliable: number
  suspicious: number
  unreliable: number
  total: number
}): EChartsOption {
  return {
    tooltip: {
      trigger: 'item',
      formatter: (p: any) => {
        const pct = data.total > 0 ? ((p.value / data.total) * 100).toFixed(1) : '0'
        return `${p.name}<br/>数量: <b>${p.value}</b><br/>占比: ${pct}%`
      },
    },
    legend: {
      bottom: 0,
      icon: 'circle',
      itemWidth: 8,
      itemHeight: 8,
      textStyle: { color: '#64748b', fontSize: 12 },
    },
    series: [
      {
        type: 'pie',
        radius: ['52%', '74%'],
        center: ['50%', '44%'],
        avoidLabelOverlap: false,
        label: {
          show: true,
          formatter: '{d}%',
          fontSize: 13,
          fontWeight: 600,
          color: '#475569',
        },
        labelLine: {
          show: true,
          length: 8,
          length2: 6,
        },
        data: [
          { value: data.reliable, name: '可靠', itemStyle: { color: '#10b981' } },
          { value: data.suspicious, name: '可疑', itemStyle: { color: '#f59e0b' } },
          { value: data.unreliable, name: '不可信', itemStyle: { color: '#94a3b8' } },
        ],
        emphasis: {
          scale: true,
          scaleSize: 6,
          itemStyle: { shadowBlur: 12, shadowColor: 'rgba(0,0,0,0.15)' },
        },
      },
    ],
  }
}
