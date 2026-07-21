<script setup lang="ts">
import { computed, watch, ref } from 'vue'
import MarkdownIt from 'markdown-it'
import hljs from 'highlight.js'
import 'highlight.js/styles/atom-one-dark.css'
import { CopyDocument } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import type { AlertDetail } from '@/types'
import { formatDateTime, formatEmpty, formatPort, copyToClipboard } from '@/utils/format'
import { maskPayload } from '@/utils/desensitize'
import { useCrossPageRouter } from '@/composables/useCrossPageRouter'

const props = defineProps<{
  modelValue: boolean
  detail: AlertDetail | null
  loading: boolean
}>()

const emit = defineEmits<{ 'update:modelValue': [val: boolean] }>()

const md = new MarkdownIt({
  html: false,
  linkify: true,
  breaks: true,
  highlight(str: string, lang: string): string {
    if (lang && hljs.getLanguage(lang)) {
      try {
        return `<pre class="hljs"><code>${hljs.highlight(str, { language: lang }).value}</code></pre>`
      } catch {
        // fallthrough
      }
    }
    return `<pre class="hljs"><code>${md.utils.escapeHtml(str)}</code></pre>`
  },
})

const attackChainHtml = computed(() => {
  const text = props.detail?.ai?.attack_chain || ''
  return text ? md.render(text) : ''
})

const handlingSuggestionHtml = computed(() => {
  const text = props.detail?.ai?.handling_suggestion || ''
  return text ? md.render(text) : ''
})

const payloadLang = computed(() => {
  const p = props.detail?.ai?.payload || ''
  if (/^(GET|POST|PUT|DELETE|HEAD|OPTIONS) \//.test(p)) return 'http'
  if (/^\s*{/.test(p) || /^\s*\[/.test(p)) return 'json'
  return 'plaintext'
})

const { goToLogExplorer } = useCrossPageRouter()

async function copyPayload() {
  if (!props.detail?.ai?.payload) return
  const ok = await copyToClipboard(props.detail.ai.payload)
  ok ? ElMessage.success('Payload 已复制') : ElMessage.error('复制失败')
}

function jumpToLog() {
  const id = props.detail?.ai?.source_alert_id
  if (id) goToLogExplorer(id)
}
</script>

<template>
  <el-drawer
    :model-value="modelValue"
    :title="`告警详情`"
    direction="rtl"
    size="50%"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div v-loading="loading" class="detail-body">
      <template v-if="detail">
        <!-- 基本信息 -->
        <section class="detail-section">
          <h4 class="section-h">基本信息</h4>
          <div class="info-grid">
            <div class="info-item">
              <span class="info-label">时间</span>
              <span class="info-value font-mono">{{ formatDateTime(detail.ai?.alert_timestamp) }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">告警类型</span>
              <span class="info-value">{{ formatEmpty(detail.ai?.soc_name) }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">威胁判定</span>
              <span class="info-value">{{ formatEmpty(detail.ai?.threat_verdict) }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">攻击结果</span>
              <span class="info-value">{{ formatEmpty(detail.ai?.attack_result) }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">源 IP:端口</span>
              <span class="info-value font-mono">{{ formatEmpty(detail.ai?.source_ip) }}:{{ formatPort(detail.ai?.source_port) }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">目的 IP:端口</span>
              <span class="info-value font-mono">{{ formatEmpty(detail.ai?.destination_ip) }}:{{ formatPort(detail.ai?.destination_port) }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">可信度</span>
              <span class="info-value font-mono">{{ formatEmpty(detail.ai?.confidence) }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">原始日志ID</span>
              <span
                v-if="detail.ai?.source_alert_id"
                class="info-value font-mono log-id-link"
                @click="jumpToLog"
              >
                {{ detail.ai.source_alert_id }}
              </span>
              <span v-else class="info-value font-mono">-</span>
            </div>
          </div>
        </section>

        <!-- 溯源分析 -->
        <section class="detail-section">
          <h4 class="section-h">溯源分析</h4>
          <div v-if="attackChainHtml" class="markdown-body" v-html="attackChainHtml"></div>
          <p v-else class="empty-text">暂无溯源分析</p>
        </section>

        <!-- 处置建议 -->
        <section class="detail-section">
          <h4 class="section-h">处置建议</h4>
          <div v-if="handlingSuggestionHtml" class="markdown-body" v-html="handlingSuggestionHtml"></div>
          <p v-else class="empty-text">暂无处置建议</p>
        </section>

        <!-- Payload -->
        <section class="detail-section">
          <div class="section-head-row">
            <h4 class="section-h">Payload</h4>
            <el-button text size="small" @click="copyPayload">
              <el-icon><CopyDocument /></el-icon>复制
            </el-button>
          </div>
          <pre v-if="detail.ai?.payload" class="payload-block"><code v-html="hljs.highlight(maskPayload(detail.ai.payload), { language: payloadLang }).value"></code></pre>
          <p v-else class="empty-text">暂无 Payload</p>
        </section>

        <!-- Response Body -->
        <section v-if="detail.ai?.response_body" class="detail-section">
          <div class="section-head-row">
            <h4 class="section-h">Response Body</h4>
            <span v-if="detail.ai?.http_status" class="http-status-badge">HTTP {{ detail.ai.http_status }}</span>
          </div>
          <pre class="payload-block"><code v-html="hljs.highlight(maskPayload(detail.ai.response_body), { language: 'plaintext' }).value"></code></pre>
        </section>

      </template>
      <div v-else-if="!loading" class="empty-text">未加载到详情</div>
    </div>
  </el-drawer>
</template>

<style scoped lang="scss">
.detail-body {
  padding: 0 $space-xl $space-xl;
}

.detail-section {
  margin-bottom: $space-xl;
  padding-bottom: $space-xl;
  border-bottom: 1px solid $color-divider;
  &:last-child {
    border-bottom: none;
  }
}

.section-h {
  font-size: 14px;
  font-weight: 600;
  color: $color-text-primary;
  margin-bottom: $space-md;
}

.section-head-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: $space-md;
  .section-h {
    margin-bottom: 0;
  }
}

.http-status-badge {
  font-size: 12px;
  font-weight: 600;
  color: $color-text-secondary;
  background: $color-bg-inset;
  padding: 2px 8px;
  border-radius: 4px;
  font-family: $font-mono;
}

.info-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: $space-md $space-xl;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
  .info-label {
    font-size: 12px;
    color: $color-text-secondary;
  }
  .info-value {
    font-size: 13px;
    color: $color-text-primary;
  }
}

.markdown-body {
  font-size: 13px;
  line-height: 1.7;
  color: $color-text-regular;
  :deep(h1), :deep(h2), :deep(h3) {
    font-size: 14px;
    margin: $space-md 0 $space-sm;
    color: $color-text-primary;
  }
  :deep(ul), :deep(ol) {
    padding-left: $space-lg;
    margin: $space-sm 0;
  }
  :deep(li) {
    margin: 4px 0;
  }
  :deep(code) {
    background: $color-bg-inset;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: $font-mono;
    font-size: 12px;
    color: $color-danger;
  }
  :deep(pre) {
    background: $color-nav-bg;
    padding: $space-md;
    border-radius: $radius-sm;
    overflow-x: auto;
    margin: $space-sm 0;
    code {
      background: transparent;
      color: #e2e8f0;
      padding: 0;
    }
  }
}

.payload-block {
  background: #f1f5f9;
  padding: $space-md;
  border-radius: $radius-sm;
  white-space: pre-wrap;
  word-break: break-word;
  overflow-wrap: anywhere;
  font-family: $font-mono;
  font-size: 12px;
  line-height: 1.6;
  max-height: 320px;
  overflow-y: auto;
  border: 1px solid $color-border-light;
  code {
    background: transparent;
    color: #334155;
    white-space: pre-wrap;
    word-break: break-word;
    overflow-wrap: anywhere;
  }
  :deep(.hljs) {
    background: transparent;
    padding: 0;
    white-space: pre-wrap;
    word-break: break-word;
    overflow-wrap: anywhere;
  }
}

.empty-text {
  color: $color-text-placeholder;
  font-size: 13px;
  padding: $space-sm 0;
}

.log-id-link {
  color: $color-primary;
  cursor: pointer;
  &:hover {
    text-decoration: underline;
  }
}
</style>
