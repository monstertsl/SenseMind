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
}>()

const chartRef = ref<HTMLDivElement>()
let chart: echarts.ECharts | null = null
let resizeObserver: ResizeObserver | null = null

function init() {
  if (!chartRef.value) return
  chart = echarts.init(chartRef.value)
  chart.setOption(props.option, true)
}

function resize() {
  chart?.resize()
}

/** 供父组件在数据就绪后显式重绘（避免依赖 watch 时机导致曲线不渲染） */
function setChartOption(opt?: EChartsOption) {
  if (!chart) {
    // chart 尚未初始化（首次数据早于 nextTick），标记后由 init 兜底
    chart = chartRef.value ? echarts.init(chartRef.value) : null
  }
  chart?.setOption(opt ?? props.option, true)
}

watch(
  () => props.option,
  (opt) => {
    chart?.setOption(opt, true)
  },
  { deep: true },
)

onMounted(async () => {
  await nextTick()
  init()
  // 用 ResizeObserver 监听容器尺寸变化：比 window.resize 更可靠，
  // 能捕捉 F12 开关、侧边栏折叠、窗口缩放等任何导致的容器宽度变化
  if (chartRef.value && typeof ResizeObserver !== 'undefined') {
    resizeObserver = new ResizeObserver(() => {
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

defineExpose({ resize, setChartOption, getInstance: () => chart })
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
