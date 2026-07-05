<script setup lang="ts">
import { computed, useSlots } from 'vue'
import CountUp from '@/components/common/CountUp.vue'
import { RISK_COLOR_MAP, RISK_LABEL_MAP } from '@/constants/esFieldMapping'
import type { RiskLevel } from '@/types'

const props = defineProps<{
  title: string
  value: number
  riskLevel?: RiskLevel
  ratio?: string
  loading?: boolean
  unit?: string
}>()

const emit = defineEmits<{ click: [] }>()
const slots = useSlots()

const stripeColor = computed(() =>
  props.riskLevel ? RISK_COLOR_MAP[props.riskLevel] : 'transparent',
)
const riskLabel = computed(() =>
  props.riskLevel ? RISK_LABEL_MAP[props.riskLevel] : '',
)
</script>

<template>
  <div
    class="metric-card risk-stripe"
    :style="{ color: stripeColor }"
    @click="emit('click')"
  >
    <div class="card-inner">
      <div class="card-head">
        <span class="card-title">{{ title }}</span>
        <span
          v-if="riskLevel && !slots.default"
          class="risk-badge"
          :style="{ background: stripeColor }"
        >{{ riskLabel }}</span>
      </div>
      <div v-if="loading" class="skeleton-block value-skeleton"></div>
      <div v-else-if="slots.default" class="card-value">
        <slot />
      </div>
      <div v-else class="card-value">
        <CountUp :value="value" />
        <span v-if="unit" class="card-unit">{{ unit }}</span>
      </div>
      <div v-if="ratio" class="card-ratio">{{ ratio }}</div>
    </div>
  </div>
</template>

<style scoped lang="scss">
.metric-card {
  background: $color-bg-elevated;
  border-radius: $radius-lg;
  border: 1px solid $color-border-light;
  box-shadow: $shadow-card;
  cursor: pointer;
  transition: all 0.2s ease;
  overflow: hidden;

  &:hover {
    box-shadow: $shadow-md;
    transform: translateY(-1px);
  }
}

.card-inner {
  padding: $space-md $space-lg $space-md $space-lg + 4;
}

.card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: $space-sm;
}

.card-title {
  font-size: 13px;
  color: $color-text-secondary;
  font-weight: 500;
}

.risk-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  color: #fff;
}

.card-value {
  display: flex;
  align-items: baseline;
  gap: 4px;
  :deep(.count-up) {
    font-size: 28px;
    font-weight: 700;
    color: $color-text-primary;
    line-height: 1.1;
  }
}

.card-unit {
  font-size: 13px;
  color: $color-text-secondary;
  font-family: $font-sans;
}

.card-ratio {
  margin-top: 4px;
  font-size: 12px;
  color: $color-text-placeholder;
}

.value-skeleton {
  width: 80px;
  height: 28px;
  margin-top: 4px;
}
</style>
