<script setup lang="ts">
/**
 * CPU / 内存 趋势图
 * - 单 Y 轴 0-100%，两条半透明面积叠加（overlaid，非 stacked）
 * - 配色：CPU #5db5da（天蓝）、内存 #d1ea80（浅黄绿）
 * - Shared Tooltip：trigger=axis，悬停同时显示该时刻 CPU 与内存
 */
import { computed, nextTick, ref, watch } from 'vue'
import BaseChart from '@/components/common/BaseChart.vue'
import { getSystemMetrics } from '@/api/metrics'
import type { MetricPoint, MetricRange, SystemMetrics } from '@/types'
import type { EChartsOption } from 'echarts'
import { CHART_FONT_FAMILY } from '@/constants/chart'

const props = defineProps<{
  range: MetricRange
  /** 配合全局刷新间隔自动更新 */
  refreshKey?: number
}>()

const data = ref<SystemMetrics | null>(null)
const loading = ref(true)

const C_CPU = '#5db5da'
const C_MEM = '#d1ea80'
const C_TEXT = '#475569'
const C_SUB = '#64748b'
const C_GRID = '#e2e8f0'

async function load() {
  try {
    data.value = await getSystemMetrics(props.range)
  } catch (e) {
    console.error('[ResourceTrendChart] 加载失败', props.range, e)
  } finally {
    loading.value = false
  }
}

watch(
  () => [props.range, props.refreshKey],
  () => {
    loading.value = true
    load()
  },
  { immediate: true },
)

const points = computed<MetricPoint[]>(() => data.value?.points ?? [])

// 数据就绪后显式重绘：仅依赖 watch(props.option) 可能因 chart 尚未初始化而漏渲染
const chartRef = ref<InstanceType<typeof BaseChart> | null>(null)
watch(
  points,
  async (pts) => {
    await nextTick()
    if (pts.length > 0) {
      chartRef.value?.setChartOption(option.value)
    }
  },
  { flush: 'post' },
)

const option = computed<EChartsOption>(() => {
  const pts = points.value
  const times = pts.map((p) => p.ts)
  return {
    color: [C_CPU, C_MEM],
    // 全局文字样式：Canvas 渲染不继承页面字体，必须显式指定
    textStyle: { fontFamily: CHART_FONT_FAMILY },
    grid: { left: 48, right: 20, top: 16, bottom: 32 },
    tooltip: {
      trigger: 'axis', // Shared Tooltip：一次显示该时刻所有序列
      axisPointer: {
        type: 'line',
        lineStyle: { color: '#94a3b8', type: 'dashed', width: 1 },
      },
      backgroundColor: '#ffffff',
      borderColor: C_GRID,
      borderWidth: 1,
      textStyle: { color: C_TEXT, fontSize: 12 },
      formatter: (params: unknown) => {
        const arr = params as Array<{ axisValue: string; seriesName: string; value: number; marker: string }>
        if (!arr?.length) return ''
        const t = new Date(arr[0].axisValue)
        const head = `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, '0')}-${String(t.getDate()).padStart(2, '0')} ${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}:${String(t.getSeconds()).padStart(2, '0')}`
        const rows = arr.map(
          (p) => `${p.marker}${p.seriesName}<span style="float:right;margin-left:20px;font-weight:600">${p.value}%</span>`,
        )
        return `<div style="font-size:12px;color:#64748b;margin-bottom:4px">${head}</div>${rows.join('<br/>')}`
      },
    },
    xAxis: {
      type: 'category',
      data: times,
      boundaryGap: false,
      axisLine: { lineStyle: { color: C_GRID } },
      axisTick: { show: false },
      axisLabel: {
        color: C_SUB,
        fontSize: 10,
        hideOverlap: true,
        formatter: (value: string) => {
          const d = new Date(value)
          const span = props.range
          const hh = String(d.getHours()).padStart(2, '0')
          const mm = String(d.getMinutes()).padStart(2, '0')
          if (span === '1h' || span === '24h') return `${hh}:${mm}`
          return `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${hh}:${mm}`
        },
      },
    },
    yAxis: {
      type: 'value',
      min: 0,
      max: 100,
      interval: 20,
      axisLabel: { color: C_SUB, fontSize: 10, formatter: '{value}%' },
      splitLine: { lineStyle: { color: C_GRID, type: 'dashed' } },
    },
    // 仅保留滚轮缩放，不显示底部时间标尺
    dataZoom: [{ type: 'inside', throttle: 50 }],
    series: [
      {
        name: 'CPU',
        type: 'line',
        data: pts.map((p) => p.cpu_percent),
        smooth: true,
        showSymbol: false,
        emphasis: { disabled: true }, // 去掉 hover 高亮，避免对比度低时难以辨认
        lineStyle: { width: 1.4, color: C_CPU },
        areaStyle: { color: C_CPU, opacity: 0.45 },
      },
      {
        name: '内存',
        type: 'line',
        data: pts.map((p) => p.memory_percent),
        smooth: true,
        showSymbol: false,
        emphasis: { disabled: true },
        lineStyle: { width: 1.4, color: C_MEM },
        areaStyle: { color: C_MEM, opacity: 0.45 },
      },
    ],
  }
})

defineExpose({ load })
</script>

<template>
  <div class="chart-card">
    <div class="chart-header">
      <h3 class="chart-title">CPU / 内存</h3>
      <!-- 图例与标题同栏，避免 ECharts 内置 legend 与 chart-header 互相遮挡 -->
      <span class="legend-inline">
        <i class="dot" :style="{ background: C_CPU }"></i>CPU
        <i class="dot" :style="{ background: C_MEM }"></i>内存
      </span>
    </div>
    <BaseChart ref="chartRef" :option="option" :loading="loading" height="260px" />
  </div>
</template>

<style scoped lang="scss">
.chart-card {
  background: $color-bg-elevated;
  border-radius: $radius-lg;
  border: 1px solid $color-border-light;
  box-shadow: $shadow-card;
  padding: $space-lg $space-xl $space-md;
  height: 100%;
  min-width: 0; // grid 子项允许收缩，避免 F12 开关后图表撑破容器
  overflow: hidden;
}
.chart-header {
  display: flex;
  align-items: baseline;
  gap: $space-sm;
  margin-bottom: $space-md;
}
.chart-title {
  font-size: 15px;
  font-weight: 600;
  color: $color-text-primary;
}
// HTML 渲染的图例：margin-left:auto 推到卡片右侧，与标题两端对齐
.legend-inline {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 12px;
  font-family: $font-sans; // 显式使用系统全局字体
  color: $color-text-regular;
  margin-left: auto;
}
.legend-inline .dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 2px;
  margin-right: 4px;
  vertical-align: middle;
}
</style>
