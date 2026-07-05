<script setup lang="ts">
import { computed } from 'vue'
import CountUp from '@/components/common/CountUp.vue'
import { calcChangeRate } from '@/utils/format'

const props = defineProps<{
  title: string
  value: number
  decimals?: number
  unit?: string
  prev?: number
  loading?: boolean
  hoverTip?: string
  compact?: boolean
}>()

const emit = defineEmits<{ click: [] }>()

const changeRate = computed(() => {
  if (props.prev === undefined || props.prev === 0) return null
  return calcChangeRate(props.value, props.prev)
})

const isUp = computed(() => (changeRate.value ?? 0) >= 0)
</script>

<template>
  <div class="ai-card" :class="{ compact }" @click="emit('click')">
    <div class="ai-card-title">{{ title }}</div>
    <div v-if="loading" class="skeleton-block" :style="compact ? 'width: 70px; height: 28px; margin: 4px 0' : 'width: 80px; height: 56px; margin: 8px 0'"></div>
    <template v-else>
      <div class="ai-card-value" :title="hoverTip">
        <CountUp :value="value" :decimals="decimals ?? 0" />
        <span v-if="unit" class="ai-card-unit">{{ unit }}</span>
      </div>
      <div v-if="changeRate !== null" class="ai-card-trend" :class="isUp ? 'up' : 'down'">
        <span class="trend-arrow">{{ isUp ? '↑' : '↓' }}</span>
        {{ Math.abs(changeRate).toFixed(1) }}% 环比
      </div>
    </template>
  </div>
</template>

<style scoped lang="scss">
.ai-card {
  background: $color-bg-elevated;
  border: 1px solid $color-border-light;
  border-radius: $radius-lg;
  padding: $space-xl $space-xl $space-lg;
  cursor: pointer;
  transition: all 0.2s ease;
  height: 100%;

  &:hover {
    border-color: $color-primary;
    box-shadow: $shadow-md;
  }

  &.compact {
    padding: $space-md $space-lg $space-md;
  }
}

.ai-card-title {
  font-size: 13px;
  color: $color-text-secondary;
  margin-bottom: $space-sm;
  font-weight: 500;
}

.ai-card-value {
  display: flex;
  align-items: baseline;
  gap: 6px;
  cursor: help;
  :deep(.count-up) {
    font-size: 48px;
    font-weight: 700;
    color: $color-primary;
    line-height: 1.1;
    letter-spacing: -0.5px;
  }
}

.compact .ai-card-value {
  :deep(.count-up) {
    font-size: 28px;
  }
}

.ai-card-unit {
  font-size: 14px;
  color: $color-text-secondary;
  font-family: $font-sans;
}

.ai-card-trend {
  margin-top: $space-sm;
  font-size: 12px;
  font-weight: 500;
  &.up {
    color: $color-success;
  }
  &.down {
    color: $color-danger;
  }
  .trend-arrow {
    font-weight: 700;
  }
}

.compact .ai-card-trend {
  margin-top: 4px;
}
</style>
