<script setup lang="ts">
import { Refresh } from '@element-plus/icons-vue'

defineProps<{
  message?: string
}>()
const emit = defineEmits<{ retry: [] }>()
</script>

<template>
  <div class="error-retry">
    <el-icon class="err-icon"><Refresh /></el-icon>
    <span class="err-text">{{ message || '加载失败' }}</span>
    <el-button size="small" type="primary" plain @click="emit('retry')">
      <el-icon><Refresh /></el-icon>重试
    </el-button>
  </div>
</template>

<style scoped lang="scss">
.error-retry {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: $space-md;
  padding: $space-2xl;
  color: $color-text-secondary;
  background: $color-bg-elevated;
  border-radius: $radius-lg;
  border: 1px dashed $color-border;
}
.err-icon {
  font-size: 28px;
  color: $color-text-placeholder;
}
.err-text {
  font-size: 13px;
}
</style>
