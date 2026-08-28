<script setup lang="ts">
/**
 * 磁盘使用率卡片
 * 从原 SystemInfoChart 三仪表盘中摘出独立成卡：
 * 磁盘是容量占用率，24h 曲线近乎平线，无时序价值，故不做趋势图，保留单值仪表盘。
 *
 * 卡片结构与 SocAttackChart 等既有图表保持一致（chart-card / chart-header）。
 */
import { computed, ref, watch } from 'vue'
import BaseChart from '@/components/common/BaseChart.vue'
import { getSystemInfo } from '@/api/metrics'
import type { SystemInfo } from '@/types'
import type { EChartsOption } from 'echarts'
import { CHART_FONT_MONO } from '@/constants/chart'

const props = defineProps<{
  /** 配合全局刷新间隔自动更新（与趋势图一致，不自建轮询） */
  refreshKey?: number
}>()

const info = ref<SystemInfo | null>(null)
const loading = ref(true)

async function load() {
  try {
    info.value = await getSystemInfo()
  } catch {
    // 静默失败，保留旧数据
  } finally {
    loading.value = false
  }
}

// 跟随全局刷新间隔刷新，不再自建 5 秒轮询
watch(
  () => props.refreshKey,
  () => {
    load()
  },
  { immediate: true },
)

/** 统一用 GB 展示，已用与总量保持同一单位 */
function formatGb(bytes: number): string {
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`
}

function getUsageColor(percent: number): string {
  if (percent >= 80) return '#ef4444'
  if (percent >= 60) return '#f59e0b'
  return '#22c55e'
}

const percent = computed(() => info.value?.disk_percent ?? 0)

const subtitle = computed(() => {
  if (!info.value) return ''
  return `${formatGb(info.value.disk_used)} / ${formatGb(info.value.disk_total)}`
})

const option = computed<EChartsOption>(() => ({
  // 不设顶层 textStyle，与旧组件 SystemInfoChart 保持一致：
  // 仪表盘名称沿用 ECharts 默认字体，仅数值（detail）使用等宽字体。
  series: [
    {
      type: 'gauge',
      startAngle: 200,
      endAngle: -20,
      min: 0,
      max: 100,
      radius: '92%',
      center: ['50%', '52%'],
      progress: { show: true, width: 14, roundCap: true, itemStyle: { color: getUsageColor(percent.value) } },
      axisLine: { lineStyle: { width: 14, color: [[1, '#e2e8f0']] } },
      pointer: { show: false },
      axisTick: { show: false },
      splitLine: { show: false },
      axisLabel: { show: false },
      anchor: { show: false },
      // 名称不再由 ECharts 绘制，改由 HTML 副标题展示，彻底避免与容量文字重叠
      title: { show: false },
      detail: {
        valueAnimation: true,
        fontSize: 24,
        fontWeight: 700,
        fontFamily: CHART_FONT_MONO, // 数值用等宽，与旧组件一致
        color: '#1e293b',
        offsetCenter: [0, '5%'],
        formatter: '{value}%',
      },
      data: [{ value: percent.value, name: '磁盘' }],
    },
  ],
}))

</script>

<template>
  <div class="chart-card">
    <div class="chart-header">
      <h3 class="chart-title">磁盘使用率</h3>
    </div>
    <div v-if="loading && !info" class="skeleton-block chart-skeleton"></div>
    <template v-else>
      <BaseChart :option="option" height="200px" />
      <!-- 容量数值放在仪表盘下方，与百分比分离，避免重叠 -->
      <div class="disk-footer">
        <span class="disk-capacity">{{ subtitle }}</span>
      </div>
    </template>
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
  display: flex;
  flex-direction: column;
  min-width: 0; // grid 子项允许收缩，避免 F12 开关后图表撑破容器
  overflow: hidden;
}

.chart-header {
  display: flex;
  align-items: baseline;
  gap: $space-sm;
  margin-bottom: $space-md;
  flex-wrap: wrap;
}

.chart-title {
  font-size: 15px;
  font-weight: 600;
  color: $color-text-primary;
}

// 容量数值与标题同行展示（等宽字体，与旧组件 .gauge-sub 一致）
.chart-skeleton {
  width: 100%;
  height: 210px;
}

// 仪表盘下方：容量数值（与百分比分离，避免重叠）
.disk-footer {
  display: flex;
  align-items: baseline;
  justify-content: center;
  gap: $space-sm;
  margin-top: -12px;
  padding-bottom: 4px;
}

// 容量数值用等宽字体，与旧组件 .gauge-sub 一致
.disk-capacity {
  font-size: 11px;
  color: $color-text-placeholder;
  font-family: $font-mono;
}
</style>
