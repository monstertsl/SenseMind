<script setup lang="ts">
import { computed } from 'vue'
import BaseChart from '@/components/common/BaseChart.vue'
import { buildThreatVerdictOption } from '@/charts/config/threatVerdictConfig'
import type { MetricsOverview } from '@/types'

const props = defineProps<{
  data: MetricsOverview['threat_verdict_distribution']
  loading?: boolean
}>()

const option = computed(() => buildThreatVerdictOption(props.data))
</script>

<template>
  <div class="chart-card">
    <div class="chart-header">
      <h3 class="chart-title">威胁判定分布</h3>
      <span class="chart-sub">可靠 / 可疑 / 不可信</span>
    </div>
    <div v-if="loading" class="skeleton-block chart-skeleton"></div>
    <BaseChart v-else :option="option" height="280px" />
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
</style>
