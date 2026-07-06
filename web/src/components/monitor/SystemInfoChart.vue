<script setup lang="ts">
import { computed, ref, onMounted, onBeforeUnmount } from 'vue'
import BaseChart from '@/components/common/BaseChart.vue'
import { getSystemInfo } from '@/api/metrics'
import type { SystemInfo } from '@/types'
import type { EChartsOption } from 'echarts'

const info = ref<SystemInfo | null>(null)
const loading = ref(true)
let timer: ReturnType<typeof setInterval> | null = null

async function fetch() {
  try {
    info.value = await getSystemInfo()
  } catch {
    // 静默失败，保留旧数据
  } finally {
    loading.value = false
  }
}

function getUsageColor(percent: number): string {
  if (percent >= 80) return '#ef4444' // 红
  if (percent >= 60) return '#f59e0b' // 黄
  return '#22c55e' // 绿
}

function buildGaugeOption(title: string, percent: number): EChartsOption {
  const color = getUsageColor(percent)
  return {
    series: [
      {
        type: 'gauge',
        startAngle: 200,
        endAngle: -20,
        min: 0,
        max: 100,
        radius: '90%',
        center: ['50%', '60%'],
        progress: {
          show: true,
          width: 14,
          roundCap: true,
          itemStyle: { color },
        },
        axisLine: {
          lineStyle: { width: 14, color: [[1, '#e2e8f0']] },
        },
        pointer: { show: false },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        anchor: { show: false },
        title: {
          show: true,
          offsetCenter: [0, '70%'],
          fontSize: 13,
          color: '#64748b',
          fontWeight: 500,
        },
        detail: {
          valueAnimation: true,
          fontSize: 24,
          fontWeight: 700,
          fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', 'HarmonyOS Sans SC', 'PingFang SC', 'Microsoft YaHei', monospace",
          color: '#1e293b',
          offsetCenter: [0, '10%'],
          formatter: '{value}%',
        },
        data: [{ value: percent, name: title }],
      },
    ],
  }
}

const cpuOption = computed(() =>
  buildGaugeOption('CPU', info.value?.cpu_percent ?? 0),
)
const memOption = computed(() =>
  buildGaugeOption('内存', info.value?.memory_percent ?? 0),
)
const diskOption = computed(() =>
  buildGaugeOption('磁盘', info.value?.disk_percent ?? 0),
)

function formatBytes(bytes: number): string {
  const gb = bytes / (1024 * 1024 * 1024)
  return gb.toFixed(1) + ' GB'
}

onMounted(() => {
  fetch()
  timer = setInterval(fetch, 5000)
})

onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
})
</script>

<template>
  <div class="chart-card">
    <div class="chart-header">
      <h3 class="chart-title">系统资源监控</h3>
      <span class="chart-sub">CPU / 内存 / 磁盘</span>
    </div>
    <div v-if="loading && !info" class="skeleton-block chart-skeleton"></div>
    <template v-else>
      <div class="gauges-grid">
        <div class="gauge-item">
          <BaseChart :option="cpuOption" height="160px" />
          <div class="gauge-sub" v-if="info">{{ info.cpu_count }} 核</div>
        </div>
        <div class="gauge-item">
          <BaseChart :option="memOption" height="160px" />
          <div class="gauge-sub" v-if="info">
            {{ formatBytes(info.memory_used) }} / {{ formatBytes(info.memory_total) }}
          </div>
        </div>
        <div class="gauge-item">
          <BaseChart :option="diskOption" height="160px" />
          <div class="gauge-sub" v-if="info">
            {{ formatBytes(info.disk_used) }} / {{ formatBytes(info.disk_total) }}
          </div>
        </div>
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
.chart-sub {
  font-size: 12px;
  color: $color-text-placeholder;
}
.chart-skeleton {
  width: 100%;
  height: 280px;
}
.gauges-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
}
.gauge-item {
  display: flex;
  flex-direction: column;
  align-items: center;
}
.gauge-sub {
  font-size: 11px;
  color: $color-text-placeholder;
  font-family: $font-mono;
  margin-top: -8px;
}
</style>
