<script setup lang="ts">
/**
 * 流量 / 丢包 趋势图
 * - 双 Y 轴：左=流量 Mbps，右=丢包数（量纲差数百倍，必须双轴，否则流量被压平）
 * - 半透明面积叠加风格，与 CPU/内存图保持一致
 * - 配色：流量 #c4e383（黄绿）、丢包 #f7916a（亮珊瑚橙，告警义）
 * - Shared Tooltip 自定义 formatter：两个序列单位不同，必须带单位否则易误读
 */
import { computed, nextTick, ref, watch } from 'vue'
import BaseChart from '@/components/common/BaseChart.vue'
import { getSystemMetrics } from '@/api/metrics'
import type { MetricPoint, MetricRange, SystemMetrics } from '@/types'
import type { EChartsOption } from 'echarts'
import { CHART_FONT_FAMILY } from '@/constants/chart'

const props = defineProps<{
  range: MetricRange
  refreshKey?: number
}>()

const data = ref<SystemMetrics | null>(null)
const loading = ref(true)

const C_FLOW = '#c4e383'
const C_DROP = '#f7916a'
const C_TEXT = '#475569'
const C_SUB = '#64748b'
const C_GRID = '#e2e8f0'

async function load() {
  try {
    data.value = await getSystemMetrics(props.range)
  } catch (e) {
    // 保留旧数据，但输出日志便于排查（此前静默吞错导致无数据时难以定位）
    console.error('[TrafficTrendChart] 加载失败', props.range, e)
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

/** 向后看的移动平均：当前点 = 过去 window 个点的均值，消除流量高速抖动 */
function movingAvg(arr: number[], window: number): number[] {
  if (window <= 1) return arr
  const result: number[] = []
  let sum = 0
  for (let i = 0; i < arr.length; i++) {
    sum += arr[i]
    if (i >= window) sum -= arr[i - window]
    result.push(sum / Math.min(i + 1, window))
  }
  return result
}

/** 流量平滑窗口：统一 60 秒均值（10 秒采样 × 6 个点） */
const trafficWindow = 6

const trafficData = computed(() =>
  movingAvg(points.value.map((p) => p.traffic_mbps), trafficWindow),
)

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

function fmtTime(iso: string): string {
  const d = new Date(iso)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

const option = computed<EChartsOption>(() => {
  const pts = points.value
  const times = pts.map((p) => p.ts)
  return {
    color: [C_FLOW, C_DROP],
    // 全局文字样式：Canvas 渲染不继承页面字体，必须显式指定
    textStyle: { fontFamily: CHART_FONT_FAMILY },
    grid: { left: 58, right: 52, top: 16, bottom: 32 },
    tooltip: {
      trigger: 'axis', // Shared Tooltip
      axisPointer: {
        type: 'line',
        lineStyle: { color: '#94a3b8', type: 'dashed', width: 1 },
      },
      backgroundColor: '#ffffff',
      borderColor: C_GRID,
      borderWidth: 1,
      textStyle: { color: C_TEXT, fontSize: 12 },
      // 双轴必须自定义 formatter 带单位，否则数值分不清是哪个轴的
      formatter: (params: unknown) => {
        const arr = params as Array<{ axisValue: string; seriesName: string; value: number; marker: string }>
        if (!arr?.length) return ''
        const head = `<div style="font-size:12px;color:#64748b;margin-bottom:4px">${fmtTime(arr[0].axisValue)}</div>`
        const rows = arr.map((p) => {
          const unit = p.seriesName === '丢包' ? '包' : 'Mbps'
          const warn =
            p.seriesName === '丢包' && p.value > 0
              ? ';color:#d97706;font-weight:700'
              : ';font-weight:600'
          return `${p.marker}${p.seriesName}<span style="float:right;margin-left:20px${warn}">${p.value.toLocaleString()} ${unit}</span>`
        })
        return head + rows.join('<br/>')
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
          const p = (n: number) => String(n).padStart(2, '0')
          if (props.range === '1h' || props.range === '24h') return `${p(d.getHours())}:${p(d.getMinutes())}`
          return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
        },
      },
    },
    yAxis: [
      {
        type: 'value',
        minInterval: 1, // 强制整数刻度（避免 0.5 之类）
        axisLabel: {
          color: C_SUB,
          fontSize: 10,
          formatter: (v: number) => Math.round(v).toLocaleString(),
        },
        splitLine: { lineStyle: { color: C_GRID, type: 'dashed' } },
      },
      {
        type: 'value',
        min: 0,
        minInterval: 1, // 丢包强制整数刻度（常态为 0 时也不会出现 0/1 这种非整数刻度）
        axisLabel: {
          color: C_SUB,
          fontSize: 10,
          formatter: (v: number) => Math.round(v).toLocaleString(),
        },
        splitLine: { show: false },
      },
    ],
    // 仅保留滚轮缩放，不显示底部时间标尺
    dataZoom: [{ type: 'inside', throttle: 50 }],
    series: [
      {
        name: '流量',
        type: 'line',
        yAxisIndex: 0,
        data: trafficData.value, // 滑动平均后的流量，消除梳子状抖动
        smooth: 0.3,
        showSymbol: false,
        emphasis: { disabled: true }, // 去掉 hover 高亮
        lineStyle: { width: 1.4, color: C_FLOW },
        areaStyle: { color: C_FLOW, opacity: 0.45 },
      },
      {
        name: '丢包',
        type: 'line',
        yAxisIndex: 1,
        data: pts.map((p) => p.drops),
        // 丢包是整数事件量，不做平滑（平滑会产生 0.几 的小数插值）
        smooth: false,
        showSymbol: false,
        step: 'middle',
        emphasis: { disabled: true },
        lineStyle: { width: 1.3, color: C_DROP },
        areaStyle: { color: C_DROP, opacity: 0.55 },
      },
    ],
  }
})

defineExpose({ load })
</script>

<template>
  <div class="chart-card">
    <div class="chart-header">
      <h3 class="chart-title">流量 / 丢包</h3>
      <!-- 图例与标题同栏，避免 ECharts 内置 legend 与 chart-header 互相遮挡 -->
      <span class="legend-inline">
        <i class="dot" :style="{ background: C_FLOW }"></i>流量
        <i class="dot" :style="{ background: C_DROP }"></i>丢包
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
