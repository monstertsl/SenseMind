<script setup lang="ts">
import { ref, watch, onMounted, onBeforeUnmount, nextTick } from 'vue'
import * as echarts from 'echarts/core'
import { BarChart, PieChart, GaugeChart, LineChart } from 'echarts/charts'
import {
  TooltipComponent,
  GridComponent,
  LegendComponent,
  GraphicComponent,
  DataZoomComponent,
  MarkLineComponent,
  MarkPointComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { EChartsOption } from 'echarts'

echarts.use([
  BarChart,
  PieChart,
  GaugeChart,
  LineChart,
  TooltipComponent,
  GridComponent,
  LegendComponent,
  GraphicComponent,
  DataZoomComponent,
  MarkLineComponent,
  MarkPointComponent,
  CanvasRenderer,
])

const props = defineProps<{
  option: EChartsOption
  height?: string
  /**
   * 是否跟随 option 变化自动 setOption（默认 true）。
   * 需要完全手动控制重绘（如趋势图切档位 notMerge 重建）的组件传 false，
   * 避免 watch 自动 merge 与手动 setChartOption 双重触发动画
   */
  autoUpdate?: boolean
}>()

const chartRef = ref<HTMLDivElement>()
let chart: echarts.ECharts | null = null
let resizeObserver: ResizeObserver | null = null

function init() {
  if (!chartRef.value) return
  chart = echarts.init(chartRef.value)
  // 不用 notMerge：保留动画过渡（切换时间档位时数据平滑渐变而非硬切）
  chart.setOption(props.option)
}

function resize() {
  chart?.resize()
}

/**
 * 供父组件在数据就绪后显式重绘（避免依赖 watch 时机导致曲线不渲染）
 * @param notMerge 是否完全替换（默认 false 走合并保留动画；
 *                   true 用于 X 轴跨度变化等结构变化场景，避免点对点错位）
 */
function setChartOption(opt?: EChartsOption, options: { notMerge?: boolean } = {}) {
  if (!chart) {
    // chart 尚未初始化（首次数据早于 nextTick），标记后由 init 兜底
    chart = chartRef.value ? echarts.init(chartRef.value) : null
  }
  chart?.setOption(opt ?? props.option, options.notMerge === true)
}

/**
 * 清空所有 series 数据（series 保留、data 置空）。
 * 用于切档位时先把旧曲线「撤下」，让 series 进入空状态；
 * 之后喂入新数据时，ECharts 会识别为「从空到有」触发入场 clip 动画。
 */
function clearSeries() {
  if (!chart) return
  const opt = chart.getOption()
  if (!opt.series) return
  const cleared = (opt.series as Array<{ data?: unknown[] }>).map((s) => ({
    ...s,
    data: [],
  }))
  chart.setOption({ series: cleared })
}

watch(
  () => props.option,
  (opt) => {
    // 手动控制重绘的组件（autoUpdate=false）不在此自动 setOption，
    // 由父组件显式 setChartOption 决定 merge/notMerge，避免双重动画
    if (!chart || props.autoUpdate === false) return
    chart?.setOption(opt)
  },
  { deep: true },
)

onMounted(async () => {
  await nextTick()
  init()
  // 用 ResizeObserver 监听容器尺寸变化：比 window.resize 更可靠，
  // 能捕捉 F12 开关、侧边栏折叠、窗口缩放等任何导致的容器宽度变化
  if (chartRef.value && typeof ResizeObserver !== 'undefined') {
    // 关键：ResizeObserver.observe() 挂载时会立即触发一次回调，
    // 若此时无条件 chart.resize() 会打断刚 init() 触发的入场动画
    // （切档位时曲线「直接跳出来」无过渡的元凶）。
    // 解决：记录上次尺寸，仅当容器尺寸真正变化时才 resize。
    let lastW = 0
    let lastH = 0
    resizeObserver = new ResizeObserver((entries) => {
      const el = entries[0]?.target as HTMLElement | undefined
      if (!el) return
      const w = el.clientWidth
      const h = el.clientHeight
      if (w === lastW && h === lastH) return // 尺寸未变（含首次挂载），跳过，勿打断动画
      lastW = w
      lastH = h
      // requestAnimationFrame 防抖：确保 CSS 布局稳定后再 resize，
      // 避免 F12 开关、断点切换等布局重排期间拿到中间态宽度
      requestAnimationFrame(() => {
        chart?.resize()
      })
    })
    resizeObserver.observe(chartRef.value)
  } else {
    window.addEventListener('resize', resize)
  }
})

onBeforeUnmount(() => {
  if (resizeObserver) {
    resizeObserver.disconnect()
    resizeObserver = null
  }
  window.removeEventListener('resize', resize)
  chart?.dispose()
  chart = null
})

defineExpose({ resize, setChartOption, clearSeries, getInstance: () => chart })
</script>

<template>
  <div ref="chartRef" class="base-chart" :style="{ height: height || '260px' }"></div>
</template>

<style scoped>
.base-chart {
  width: 100%;
  /* 关键：grid/flex 子项默认 min-width:auto 会阻止收缩导致 canvas 撑破容器，
     设 0 后才能在 F12 开关等宽度变化时正确自适应 */
  min-width: 0;
}
</style>
