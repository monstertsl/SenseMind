<script setup lang="ts">
import { ref, watch, onMounted } from 'vue'

const props = withDefaults(
  defineProps<{
    value: number
    duration?: number
    decimals?: number
  }>(),
  { duration: 800, decimals: 0 },
)

const display = ref(0)

function animate(from: number, to: number) {
  const start = performance.now()
  const step = (now: number) => {
    const progress = Math.min((now - start) / props.duration, 1)
    // easeOutCubic
    const eased = 1 - Math.pow(1 - progress, 3)
    display.value = from + (to - from) * eased
    if (progress < 1) requestAnimationFrame(step)
    else display.value = to
  }
  requestAnimationFrame(step)
}

watch(
  () => props.value,
  (n, o) => animate(o ?? 0, n),
)

onMounted(() => animate(0, props.value))
</script>

<template>
  <span class="count-up font-mono count-animate">{{ display.toFixed(decimals) }}</span>
</template>

<style scoped lang="scss">
.count-up {
  display: inline-block;
  font-feature-settings: 'tnum';
}
</style>
