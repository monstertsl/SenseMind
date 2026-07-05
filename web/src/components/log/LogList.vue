<script setup lang="ts">
import { Link } from '@element-plus/icons-vue'
import type { LogItem } from '@/types'
import { formatDateTime } from '@/utils/format'

defineProps<{
  data: LogItem[]
  loading: boolean
}>()

const emit = defineEmits<{
  rowClick: [row: LogItem]
  aiClick: [row: LogItem]
}>()

function summarize(source: Record<string, any>): string {
  const parts: string[] = []
  if (source.source?.ip) parts.push(`源=${source.source.ip}`)
  if (source.destination?.ip) parts.push(`目的=${source.destination.ip}`)
  if (source.destination?.port) parts.push(`端口=${source.destination.port}`)
  const sig = source.suricata?.eve?.alert?.signature
  if (sig) parts.push(sig)
  if (source.event?.dataset) parts.push(`[${source.event.dataset}]`)
  return parts.join(' ') || JSON.stringify(source).slice(0, 120)
}
</script>

<template>
  <div class="log-list">
    <div
      v-for="item in data"
      :key="item._id"
      class="log-row"
      @click="emit('rowClick', item)"
    >
      <div class="log-row-main">
        <span class="log-time font-mono">{{ formatDateTime(item._source?.['@timestamp']) }}</span>
        <span class="log-index">{{ item._index }}</span>
        <span
          v-if="item.has_ai_analysis"
          class="ai-badge"
          title="存在 AI 研判"
          @click.stop="emit('aiClick', item)"
        >
          <el-icon><Link /></el-icon>AI研判
        </span>
      </div>
      <div class="log-row-summary text-ellipsis">
        {{ summarize(item._source) }}
      </div>
    </div>

    <div v-if="!data.length && !loading" class="empty-state">
      <p>未检索到日志</p>
      <span>请检查检索条件或扩大时间范围</span>
    </div>
  </div>
</template>

<style scoped lang="scss">
.log-list {
  display: flex;
  flex-direction: column;
}

.log-row {
  padding: $space-md $space-xl;
  border-bottom: 1px solid $color-divider;
  cursor: pointer;
  transition: background 0.15s ease;
  &:hover {
    background: rgba(0, 92, 173, 0.04);
  }
}

.log-row-main {
  display: flex;
  align-items: center;
  gap: $space-md;
  margin-bottom: 4px;
}

.log-time {
  font-size: 12px;
  color: $color-text-regular;
  font-weight: 500;
}

.log-index {
  font-size: 11px;
  color: $color-text-placeholder;
  background: $color-bg-soft;
  padding: 1px 6px;
  border-radius: 3px;
  font-family: $font-mono;
}

.ai-badge {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  font-size: 11px;
  color: $color-primary;
  background: rgba(0, 92, 173, 0.1);
  padding: 1px 6px;
  border-radius: 3px;
  font-weight: 500;
  &:hover {
    background: rgba(0, 92, 173, 0.2);
  }
}

.log-row-summary {
  font-size: 12px;
  color: $color-text-secondary;
  font-family: $font-mono;
}

.empty-state {
  padding: $space-2xl;
  text-align: center;
  color: $color-text-placeholder;
  p {
    font-size: 14px;
    margin-bottom: 4px;
  }
  span {
    font-size: 12px;
  }
}
</style>
