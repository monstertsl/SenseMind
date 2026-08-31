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
/** 切档位标记：range 变化时先清空旧图（旧的不要），新数据到后再 notMerge 重建展开 */
const switching = ref(false)

const C_FLOW = '#c4e383'
const C_DROP = '#f7916a'
const C_TEXT = '#475569'
const C_SUB = '#64748b'
const C_GRID = '#e2e8f0'

async function load() {
  try {
    const d = await getSystemMetrics(props.range)
    // 若加载期间档位又变了（快速连点），丢弃过期响应，避免旧档数据覆盖
    if (d.range !== props.range) return
    data.value = d
  } catch (e) {
    // 保留旧数据，但输出日志便于排查（此前静默吞错导致无数据时难以定位）
    console.error('[TrafficTrendChart] 加载失败', props.range, e)
  } finally {
    loading.value = false
  }
}

let prevRange: MetricRange | undefined = undefined
watch(
  () => [props.range, props.refreshKey],
  ([range]) => {
    // 切档位（非单纯刷新）：立即清空旧数据，图表瞬间归空，不做形变过渡
    if (prevRange !== undefined && range !== prevRange) {
      switching.value = true
      data.value = null
      // 关键：真正把旧曲线从图表上「撤下」，让 series 进入空状态。
      // 之后新数据到位时 ECharts 才会识别为「从空到有」触发入场 clip 划线动画；
      // 否则 notMerge 重建被当作「更新」走 animationDurationUpdate(=0) 瞬间跳变。
      chartRef.value?.clearSeries()
    }
    prevRange = range as MetricRange
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

/**
 * 流量滑动平均窗口：
 * - 1h 档：后端返回 10 秒原始点，需滑动平均（窗口 6 = 60 秒）消除抖动
 * - 24h/7d 档：后端已按 10 分钟/1 小时桶聚合（均值），无需再平滑
 */
const trafficWindow = computed(() => (props.range === '1h' ? 6 : 1))

/** 滑动平均后的流量，带时间戳（time 轴需 [时间戳, 数值] 二维数组） */
const trafficData = computed(() => {
  const smoothed = movingAvg(points.value.map((p) => p.traffic_mbps), trafficWindow.value)
  return points.value.map((p, i) => [new Date(p.ts).getTime(), smoothed[i]])
})

// 数据就绪后显式重绘：仅依赖 watch(props.option) 可能因 chart 尚未初始化而漏渲染
const chartRef = ref<InstanceType<typeof BaseChart> | null>(null)
/** 图表外层容器：用于播放「从左往右揭开」的纯 CSS 展开动画 */
const wrapRef = ref<HTMLDivElement | null>(null)

/**
 * 重播展开动画：移除 class → 强制重排 → 重新加上。
 * 用纯 CSS clip-path 实现，不依赖 ECharts 内部动画机制（稳定可控）。
 */
function playReveal() {
  const el = wrapRef.value
  if (!el) return
  el.classList.remove('reveal')
  void el.offsetWidth // 强制重排，确保动画重新播放（否则同名 class 不会重启）
  el.classList.add('reveal')
}

watch(
  points,
  async (pts) => {
    await nextTick()
    if (pts.length === 0) return
    if (switching.value) {
      // 切档位场景：旧曲线已清空，喂新数据的同时播放从左往右展开动画
      switching.value = false
      chartRef.value?.setChartOption(option.value)
      playReveal()
    } else {
      // 数据刷新（range 不变）走合并，平滑，不播动画
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
  return {
    color: [C_FLOW, C_DROP],
    // 全局文字样式：Canvas 渲染不继承页面字体，必须显式指定
    textStyle: { fontFamily: CHART_FONT_FAMILY },
    // 动画策略：切档位的「从左往右展开」效果由外层 .chart-reveal 的纯 CSS clip-path
    // 动画实现（见样式段），不依赖 ECharts 内部动画——后者会被 resize 打断且触发条件苛刻。
    // 此处整体关闭 ECharts 动画，避免其内部过渡（轴张开、点对点形变）与 CSS 动画打架。
    // universalTransition 是 SERIES 级配置（见各 series 的 universalTransition:false），
    // 写顶层无效！它默认开启，切档位时把旧点形变到新位置造成"从右滑出"。
    animation: false,
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
        // time 轴下 value 为 [时间戳, 数值]，axisValue 为时间戳数值
        const arr = params as Array<{
          axisValue: number
          value: [number, number]
          seriesName: string
          marker: string
        }>
        if (!arr?.length) return ''
        const head = `<div style="font-size:12px;color:#64748b;margin-bottom:4px">${fmtTime(new Date(arr[0].axisValue).toISOString())}</div>`
        const rows = arr.map((p) => {
          const v = Array.isArray(p.value) ? p.value[1] : p.value
          const unit = p.seriesName === '丢包' ? '包' : 'Mbps'
          const warn =
            p.seriesName === '丢包' && v > 0
              ? ';color:#d97706;font-weight:700'
              : ';font-weight:600'
          return `${p.marker}${p.seriesName}<span style="float:right;margin-left:20px${warn}">${Number(v).toLocaleString()} ${unit}</span>`
        })
        return head + rows.join('<br/>')
      },
    },
    xAxis: {
      // 时间轴：切换档位时点按真实时间戳插值移动，产生收缩/张开的缩放过渡
      type: 'time',
      boundaryGap: false,
      axisLine: { lineStyle: { color: C_GRID } },
      axisTick: { show: false },
      axisLabel: {
        color: C_SUB,
        fontSize: 10,
        hideOverlap: true,
        formatter: (value: number) => {
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
        // 关键：universalTransition 是 series 级配置，必须写在这里才能生效！
        // 它默认开启，切档位时会把旧点形变到新位置（X 轴跨度变化 24 倍），
        // 造成整条线从右侧滑出的「拉屎」效果。1h↔24h 点数相同(360)会完美配对
        // 触发形变，7d(336)点数不同配对失败反而正常。
        universalTransition: false,
        yAxisIndex: 0,
        data: trafficData.value, // 滑动平均后的流量（带时间戳），消除梳子状抖动
        smooth: 0.3,
        showSymbol: false,
        emphasis: { disabled: true }, // 去掉 hover 高亮
        lineStyle: { width: 1.4, color: C_FLOW },
        areaStyle: { color: C_FLOW, opacity: 0.45 },
      },
      {
        name: '丢包',
        type: 'line',
        universalTransition: false,
        yAxisIndex: 1,
        data: pts.map((p) => [new Date(p.ts).getTime(), p.drops]),
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
    <div ref="wrapRef" class="chart-reveal">
      <BaseChart ref="chartRef" :option="option" :loading="loading" height="260px" :auto-update="false" />
    </div>
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
// 切档位展开动画：clip-path 从左往右揭开，纯 CSS 实现，
// 不依赖 ECharts 内部动画（其入场动画会被 resize 等打断，不可靠）
.chart-reveal.reveal {
  animation: chart-reveal 800ms cubic-bezier(0.25, 0.46, 0.45, 0.94) both;
}
@keyframes chart-reveal {
  from {
    clip-path: inset(0 100% 0 0);
  }
  to {
    clip-path: inset(0 0 0 0);
  }
}
</style>
