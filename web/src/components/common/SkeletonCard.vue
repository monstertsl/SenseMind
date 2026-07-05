<script setup lang="ts">
// 骨架屏卡片占位
withDefaults(defineProps<{ lines?: number; height?: string }>(), {
  lines: 2,
  height: '120px',
})
</script>

<template>
  <div class="skeleton-card" :style="{ minHeight: height }">
    <div class="skeleton-line skeleton-block" style="width: 40%; height: 12px"></div>
    <div class="skeleton-line skeleton-block" style="width: 60%; height: 32px; margin-top: 12px"></div>
    <div v-for="i in lines - 1" :key="i" class="skeleton-line skeleton-block" style="width: 30%; height: 10px; margin-top: 8px"></div>
  </div>
</template>

<style scoped lang="scss">
.skeleton-card {
  padding: $space-xl;
  background: $color-bg-elevated;
  border-radius: $radius-lg;
  border: 1px solid $color-border-light;
}
.skeleton-line {
  margin-bottom: 4px;
}
</style>
