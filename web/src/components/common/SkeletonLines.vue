<script setup lang="ts">
// 文本/详情骨架屏占位：替代抽屉、配置区块里的 v-loading 转圈
const props = withDefaults(defineProps<{ rows?: number; lineHeight?: string }>(), {
  rows: 4,
  lineHeight: '12px',
})

const WIDTHS = ['92%', '78%', '86%', '64%', '90%', '72%']
const rowIndexes = Array.from({ length: props.rows }, (_, index) => index + 1)

function lineWidth(row: number): string {
  return WIDTHS[(row - 1) % WIDTHS.length]
}
</script>

<template>
  <div class="skeleton-lines">
    <div
      v-for="row in rowIndexes"
      :key="row"
      class="skeleton-block"
      :style="{ width: lineWidth(row), height: lineHeight }"
    ></div>
  </div>
</template>

<style scoped lang="scss">
.skeleton-lines {
  display: flex;
  flex-direction: column;
  gap: 10px;
  width: 100%;
}
</style>
