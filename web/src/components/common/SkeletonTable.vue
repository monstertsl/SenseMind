<script setup lang="ts">
// 表格骨架屏占位：替代 el-table 的 v-loading 转圈
const props = withDefaults(defineProps<{ rows?: number; columns?: number }>(), {
  rows: 6,
  columns: 5,
})

const WIDTHS = ['72%', '48%', '86%', '56%', '64%']

function cellWidth(row: number, col: number): string {
  return WIDTHS[(row + col) % WIDTHS.length]
}

const columnIndexes = Array.from({ length: props.columns }, (_, index) => index + 1)
const rowIndexes = Array.from({ length: props.rows }, (_, index) => index + 1)
</script>

<template>
  <div class="skeleton-table">
    <div class="skeleton-row skeleton-head">
      <div v-for="col in columnIndexes" :key="col" class="skeleton-cell">
        <div class="skeleton-block head-block"></div>
      </div>
    </div>
    <div v-for="row in rowIndexes" :key="row" class="skeleton-row">
      <div v-for="col in columnIndexes" :key="col" class="skeleton-cell">
        <div class="skeleton-block body-block" :style="{ width: cellWidth(row, col) }"></div>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
.skeleton-table {
  width: 100%;
  border: 1px solid $color-border-light;
  border-radius: $radius-md;
  overflow: hidden;
}

.skeleton-row {
  display: grid;
  grid-auto-flow: column;
  grid-auto-columns: 1fr;
  align-items: center;
  gap: 16px;
  padding: 12px 16px;

  & + .skeleton-row {
    border-top: 1px solid $color-border-light;
  }
}

.skeleton-head {
  background: #eef1f6;
}

.skeleton-cell {
  display: flex;
  align-items: center;
}

.head-block {
  width: 56%;
  height: 12px;
}

.body-block {
  height: 12px;
}
</style>
