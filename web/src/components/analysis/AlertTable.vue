<script setup lang="ts">
import { computed } from 'vue'
import { ElTooltip, ElMessage } from 'element-plus'
import { CopyDocument, Link } from '@element-plus/icons-vue'
import type { AlertItem } from '@/types'
import { ES_FIELD_MAPPING, getSocNameTagType } from '@/constants/esFieldMapping'
import { formatDateTime, formatPort, formatEmpty, formatConfidence, copyToClipboard } from '@/utils/format'
import { maskPayload } from '@/utils/desensitize'
import { useCrossPageRouter } from '@/composables/useCrossPageRouter'

const props = defineProps<{
  data: AlertItem[]
  loading: boolean
  page: number
  pageSize: number
}>()

const emit = defineEmits<{
  sort: [field: string, order: 'asc' | 'desc']
  rowClick: [row: AlertItem]
  ipClick: [ip: string]
}>()

const { goToLogExplorer } = useCrossPageRouter()

// 表格列序严格按规格 12 列
const columns = ES_FIELD_MAPPING

async function handleCopy(text: string, e: Event) {
  e.stopPropagation()
  const ok = await copyToClipboard(text)
  ok ? ElMessage.success('已复制') : ElMessage.error('复制失败')
}

function handleIpClick(ip: string, e: Event) {
  e.stopPropagation()
  if (ip) {
    emit('ipClick', ip)
    handleCopy(ip, e)
  }
}

function handleSourceAlertIdClick(id: string, e: Event) {
  e.stopPropagation()
  if (id) goToLogExplorer(id)
}

function truncate(text: string, len = 40): string {
  if (!text) return ''
  return text.length > len ? text.slice(0, len) + '…' : text
}

// 关键字高亮（威胁名）
function highlightKeyword(text: string, keyword?: string): string {
  if (!text) return ''
  if (!keyword) return text
  const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return text.replace(new RegExp(escaped, 'gi'), (m) => `<mark class="hl">${m}</mark>`)
}

const props_keyword = computed(() => '')

function onSortChange({ prop, order }: { prop: string; order: string | null }) {
  if (!order) {
    emit('sort', 'ai.alert_timestamp', 'desc')
  } else {
    emit('sort', prop, order === 'ascending' ? 'asc' : 'desc')
  }
}
</script>

<template>
  <div class="alert-table-wrap">
    <el-table
      :data="data"
      v-loading="loading"
      :border="false"
      stripe
      size="small"
      style="width: 100%"
      :header-cell-style="{ background: '#eef1f6', color: '#475569', fontWeight: 600 }"
      @row-click="emit('rowClick', $event as any)"
      @sort-change="onSortChange"
    >
      <!-- 1. 原始日志时间 -->
      <el-table-column
        prop="ai.alert_timestamp"
        label="原始日志时间"
        width="180"
        sortable="custom"
      >
        <template #default="{ row }">
          <span class="font-mono">{{ formatDateTime(row.ai?.alert_timestamp) }}</span>
        </template>
      </el-table-column>

      <!-- 2. 源IP -->
      <el-table-column prop="ai.source_ip" label="源IP" width="110">
        <template #default="{ row }">
          <span
            class="ip-cell"
            :title="`点击回填: ${row.ai?.source_ip}`"
            @click="handleIpClick(row.ai?.source_ip, $event)"
          >
            {{ formatEmpty(row.ai?.source_ip) }}
            <el-icon class="copy-icon"><CopyDocument /></el-icon>
          </span>
        </template>
      </el-table-column>

      <!-- 3. 源端口 -->
      <el-table-column prop="ai.source_port" label="源端口" width="90" align="right">
        <template #default="{ row }">
          <span class="font-mono">{{ formatPort(row.ai?.source_port) }}</span>
        </template>
      </el-table-column>

      <!-- 4. 目的IP -->
      <el-table-column prop="ai.destination_ip" label="目的IP" width="110">
        <template #default="{ row }">
          <span
            class="ip-cell"
            :title="`点击回填: ${row.ai?.destination_ip}`"
            @click="handleIpClick(row.ai?.destination_ip, $event)"
          >
            {{ formatEmpty(row.ai?.destination_ip) }}
            <el-icon class="copy-icon"><CopyDocument /></el-icon>
          </span>
        </template>
      </el-table-column>

      <!-- 5. 目的端口 -->
      <el-table-column prop="ai.destination_port" label="目的端口" width="90" align="right">
        <template #default="{ row }">
          <span class="font-mono">{{ formatPort(row.ai?.destination_port) }}</span>
        </template>
      </el-table-column>

      <!-- 6. 告警类型 -->
      <el-table-column prop="ai.soc_name" label="告警类型" width="130">
        <template #default="{ row }">
          <el-tag
            v-if="row.ai?.soc_name"
            :type="getSocNameTagType(row.ai.soc_name)"
            size="small"
            effect="light"
          >
            {{ row.ai.soc_name }}
          </el-tag>
          <span v-else class="empty-placeholder">-</span>
        </template>
      </el-table-column>

      <!-- 7. 威胁名 -->
      <el-table-column prop="ai.alert_signature" label="威胁名" width="240" show-overflow-tooltip>
        <template #default="{ row }">
          <span
            class="text-ellipsis"
            v-html="highlightKeyword(row.ai?.alert_signature || '', props_keyword)"
          ></span>
        </template>
      </el-table-column>

      <!-- 8. 可信度 -->
      <el-table-column prop="ai.confidence" label="可信度" width="90">
        <template #default="{ row }">
          <span class="font-mono">{{ formatConfidence(row.ai?.confidence) }}</span>
        </template>
      </el-table-column>

      <!-- 9. 溯源分析（默认隐藏，Tooltip 摘要） -->
      <el-table-column prop="ai.attack_chain" label="溯源分析" width="120">
        <template #default="{ row }">
          <el-tooltip
            v-if="row.ai?.attack_chain"
            :content="row.ai.attack_chain"
            placement="top"
            :show-after="300"
            popper-class="chain-tooltip"
          >
            <span class="text-ellipsis summary-cell">{{ truncate(row.ai.attack_chain) }}</span>
          </el-tooltip>
          <span v-else class="empty-placeholder">-</span>
        </template>
      </el-table-column>

      <!-- 10. 处置建议（默认隐藏，Tooltip 摘要） -->
      <el-table-column prop="ai.handling_suggestion" label="处置建议" width="120">
        <template #default="{ row }">
          <el-tooltip
            v-if="row.ai?.handling_suggestion"
            :content="row.ai.handling_suggestion"
            placement="top"
            :show-after="300"
            popper-class="chain-tooltip"
          >
            <span class="text-ellipsis summary-cell">{{ truncate(row.ai.handling_suggestion) }}</span>
          </el-tooltip>
          <span v-else class="empty-placeholder">-</span>
        </template>
      </el-table-column>

      <!-- 11. Payload（表格不显示，仅详情抽屉展示） -->

      <!-- 12. 原始日志ID -->
      <el-table-column prop="ai.source_alert_id" label="原始日志ID" width="190">
        <template #default="{ row }">
          <span
            v-if="row.ai?.source_alert_id"
            class="log-id-cell"
            :title="`跳转日志中心检索: ${row.ai.source_alert_id}`"
            @click="handleSourceAlertIdClick(row.ai.source_alert_id, $event)"
          >
            <span class="font-mono">{{ row.ai.source_alert_id }}</span>
            <el-icon class="link-icon"><Link /></el-icon>
          </span>
          <span v-else class="empty-placeholder">-</span>
        </template>
      </el-table-column>

      <template #empty>
        <div class="table-empty">
          <el-icon class="empty-icon"><Document /></el-icon>
          <p>暂无告警数据</p>
        </div>
      </template>
    </el-table>
  </div>
</template>

<style scoped lang="scss">
.alert-table-wrap {
  background: $color-bg-elevated;
  border-radius: $radius-lg;
  border: 1px solid $color-border-light;
  overflow: hidden;
}

.ip-cell {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: $color-primary;
  cursor: pointer;
  font-family: $font-mono;
  &:hover {
    text-decoration: underline;
    .copy-icon {
      opacity: 1;
    }
  }
  .copy-icon {
    font-size: 12px;
    opacity: 0.5;
  }
}

.summary-cell {
  color: $color-text-secondary;
  cursor: help;
  display: inline-block;
  max-width: 100%;
}

.payload-cell {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  background: $color-nav-bg;
  color: #e2e8f0;
  padding: 2px 8px;
  border-radius: $radius-sm;
  font-family: $font-mono;
  font-size: 11px;
  cursor: pointer;
  max-width: 100%;
  span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .copy-icon {
    font-size: 11px;
    opacity: 0.7;
  }
  &:hover .copy-icon {
    opacity: 1;
  }
}

.log-id-cell {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: $color-text-placeholder;
  font-size: 12px;
  cursor: pointer;
  &:hover {
    color: $color-primary;
    .link-icon {
      opacity: 1;
    }
  }
  .link-icon {
    font-size: 11px;
    opacity: 0.5;
  }
}

.empty-placeholder {
  color: $color-text-placeholder;
}

.table-empty {
  padding: $space-2xl;
  text-align: center;
  color: $color-text-placeholder;
  .empty-icon {
    font-size: 36px;
    margin-bottom: $space-sm;
  }
}

:deep(.hl) {
  background: rgba(245, 158, 11, 0.25);
  color: $color-warning;
  padding: 0 2px;
  border-radius: 2px;
}
</style>

<style lang="scss">
// 全局 tooltip 样式（非 scoped）
.chain-tooltip {
  max-width: 480px;
  line-height: 1.6;
}
.payload-tooltip {
  max-width: 600px;
  .payload-pre {
    background: $color-nav-bg;
    color: #e2e8f0;
    padding: 12px;
    border-radius: $radius-sm;
    font-family: $font-mono;
    font-size: 12px;
    max-height: 320px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }
}
</style>
