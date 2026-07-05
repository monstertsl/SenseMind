import type { EChartsOption } from 'echarts'

// 威胁分析来源 - 环形图（系统告警 / 语义分析）
export function buildThreatSourceOption(data: {
  system_alert: number
  semantic_analysis: number
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
          { value: data.system_alert, name: '系统告警', itemStyle: { color: '#3b82f6' } },
          { value: data.semantic_analysis, name: '语义分析', itemStyle: { color: '#8b5cf6' } },
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
