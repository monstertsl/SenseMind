<script setup lang="ts">
import { computed, ref } from 'vue'
import { CopyDocument, Link, MagicStick } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { LogItem } from '@/types'
import { formatDateTime, copyToClipboard } from '@/utils/format'
import { maskSensitive } from '@/utils/desensitize'
import { triggerAiAnalysis } from '@/api/logs'

const props = defineProps<{
  modelValue: boolean
  log: LogItem | null
  loading: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [val: boolean]
  viewAi: []
  analyzed: []
}>()

const aiAnalyzing = ref(false)

// 判断是否为 soc-* 原始日志（非 soc-ai-*）
const isRawLog = computed(() => {
  if (!props.log) return false
  return !props.log.has_ai_analysis && props.log._index && !props.log._index.includes('soc-ai')
})

async function handleTriggerAi() {
  if (!props.log) return
  try {
    await ElMessageBox.confirm('确认对这条日志触发 AI 研判分析吗？', 'AI 研判', { type: 'info' })
  } catch {
    return
  }
  aiAnalyzing.value = true
  try {
    await triggerAiAnalysis(props.log._id)
    ElMessage.success('AI 研判完成，结果已写入 soc-ai-* 索引')
    emit('analyzed')
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || 'AI 研判失败')
  } finally {
    aiAnalyzing.value = false
  }
}

// 敏感字段集合（脱敏展示值）
const SENSITIVE_KEYS = ['password', 'passwd', 'pwd', 'token', 'secret', 'authorization']

interface TreeNode {
  key: string
  value: any
  path: string
  type: 'object' | 'array' | 'string' | 'number' | 'boolean' | 'null'
  depth: number
  children?: TreeNode[]
  expanded?: boolean
  sensitive?: boolean
}

function buildTree(obj: any, key = 'root', path = '', depth = 0, parentSensitive = false): TreeNode {
  const sensitive = parentSensitive || SENSITIVE_KEYS.some((k) => key.toLowerCase().includes(k))
  if (obj === null || obj === undefined) {
    return { key, value: null, path, type: 'null', depth, sensitive }
  }
  if (Array.isArray(obj)) {
    return {
      key,
      value: obj,
      path,
      type: 'array',
      depth,
      sensitive,
      children: obj.map((v, i) => buildTree(v, `[${i}]`, `${path}[${i}]`, depth + 1, sensitive)),
      expanded: depth < 2,
    }
  }
  if (typeof obj === 'object') {
    return {
      key,
      value: obj,
      path,
      type: 'object',
      depth,
      sensitive,
      children: Object.entries(obj).map(([k, v]) =>
        buildTree(v, k, path ? `${path}.${k}` : k, depth + 1, sensitive),
      ),
      expanded: depth < 2,
    }
  }
  const t: TreeNode['type'] = typeof obj === 'number' ? 'number' : typeof obj === 'boolean' ? 'boolean' : 'string'
  return { key, value: obj, path, type: t, depth, sensitive }
}

const root = computed<TreeNode | null>(() => {
  if (!props.log?._source) return null
  return buildTree(props.log._source)
})

const expandedPaths = ref(new Set<string>(['root']))

function toggle(n: TreeNode) {
  const path = n.path || 'root'
  if (expandedPaths.value.has(path)) {
    expandedPaths.value.delete(path)
  } else {
    expandedPaths.value.add(path)
  }
}

function isExpanded(n: TreeNode): boolean {
  return expandedPaths.value.has(n.path || 'root')
}

const flatNodes = computed<TreeNode[]>(() => {
  const result: TreeNode[] = []
  if (!root.value) return result
  function walk(n: TreeNode) {
    result.push(n)
    if (n.children && isExpanded(n)) {
      n.children.forEach(walk)
    }
  }
  walk(root.value)
  return result
})

function displayValue(n: TreeNode): string {
  if (n.type === 'null') return 'null'
  if (n.sensitive && n.type === 'string') return maskSensitive(String(n.value))
  return String(n.value)
}

async function copyField(n: TreeNode, e: Event) {
  e.stopPropagation()
  const ok = await copyToClipboard(typeof n.value === 'object' ? JSON.stringify(n.value) : String(n.value))
  ok ? ElMessage.success(`已复制 ${n.key}`) : ElMessage.error('复制失败')
}

function onContextField(n: TreeNode) {
  // 简化：右键复制字段路径
  copyToClipboard(n.path).then((ok) => ok && ElMessage.success(`字段路径已复制: ${n.path}`))
}
</script>

<template>
  <el-drawer
    :model-value="modelValue"
    title="日志详情"
    direction="rtl"
    size="50%"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div v-loading="loading" class="detail-body">
      <template v-if="log">
        <!-- 顶部信息 -->
        <div class="log-meta">
          <div class="meta-row">
            <span class="meta-label">时间</span>
            <span class="font-mono">{{ formatDateTime(log._source?.['@timestamp']) }}</span>
          </div>
          <div class="meta-row">
            <span class="meta-label">索引</span>
            <span class="font-mono">{{ log._index }}</span>
          </div>
          <div class="meta-row">
            <span class="meta-label">_id</span>
            <span class="font-mono">{{ log._id }}</span>
          </div>
        </div>

        <!-- AI 研判跳转（soc-ai-* 日志） -->
        <el-button
          v-if="log.has_ai_analysis"
          type="primary"
          class="ai-jump-btn"
          @click="emit('viewAi')"
        >
          <el-icon><Link /></el-icon>查看 AI 研判
        </el-button>

        <!-- AI 研判触发（soc-* 原始日志） -->
        <el-button
          v-if="isRawLog"
          type="primary"
          class="ai-jump-btn"
          :loading="aiAnalyzing"
          @click="handleTriggerAi"
        >
          <el-icon v-if="!aiAnalyzing"><MagicStick /></el-icon>AI 研判
        </el-button>

        <!-- JSON 树形视图 -->
        <div class="json-tree">
          <div
            v-for="n in flatNodes"
            :key="n.path || 'root'"
            class="json-node"
            :class="{ leaf: !n.children?.length, sensitive: n.sensitive }"
            :style="{ paddingLeft: n.depth * 16 + 12 + 'px' }"
          >
            <span
              v-if="n.children?.length"
              class="toggle"
              @click="toggle(n)"
            >
              {{ isExpanded(n) ? '▼' : '▶' }}
            </span>
            <span v-else class="toggle-placeholder"></span>
            <span class="node-key" @contextmenu.prevent="onContextField(n)">{{ n.key }}:</span>
            <template v-if="!n.children?.length">
              <span class="node-value" :class="n.type" @contextmenu.prevent="onContextField(n)">
                {{ displayValue(n) }}
              </span>
              <el-icon class="copy-icon" @click="copyField(n, $event)"><CopyDocument /></el-icon>
            </template>
            <template v-else>
              <span class="node-bracket">
                {{ n.type === 'array' ? '[' : '{' }}
                <span class="bracket-count">{{ n.children.length }}</span>
                {{ isExpanded(n) ? '' : n.type === 'array' ? ' ]' : ' }' }}
              </span>
            </template>
          </div>
        </div>
      </template>
      <div v-else-if="!loading" class="empty-text">未加载到日志</div>
    </div>
  </el-drawer>
</template>

<style scoped lang="scss">
.detail-body {
  padding: 0 $space-xl $space-xl;
}

.log-meta {
  background: $color-bg-soft;
  border-radius: $radius-sm;
  padding: $space-md;
  margin-bottom: $space-md;
  display: flex;
  flex-direction: column;
  gap: $space-xs;
}

.meta-row {
  display: flex;
  gap: $space-md;
  font-size: 12px;
  .meta-label {
    color: $color-text-secondary;
    min-width: 40px;
  }
}

.ai-jump-btn {
  margin-bottom: $space-md;
  width: 100%;
}

.json-tree {
  background: $color-nav-bg;
  border-radius: $radius-sm;
  padding: $space-md;
  font-family: $font-mono;
  font-size: 12px;
  max-height: 60vh;
  overflow: auto;
}

.json-node {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 2px 0;
  line-height: 1.5;
  &:hover {
    background: rgba(255, 255, 255, 0.05);
    .copy-icon {
      opacity: 1;
    }
  }
}

.toggle {
  cursor: pointer;
  color: #94a3b8;
  width: 12px;
  flex-shrink: 0;
  user-select: none;
}

.toggle-placeholder {
  width: 12px;
  flex-shrink: 0;
}

.node-key {
  color: #93c5fd;
}

.node-value {
  color: #e2e8f0;
  &.string {
    color: #86efac;
  }
  &.number {
    color: #fbbf24;
  }
  &.boolean {
    color: #f0abfc;
  }
  &.null {
    color: #94a3b8;
  }
}

.node-bracket {
  color: #94a3b8;
  .bracket-count {
    color: #64748b;
    font-size: 10px;
    margin: 0 2px;
  }
}

.copy-icon {
  font-size: 11px;
  color: #94a3b8;
  opacity: 0.4;
  cursor: pointer;
  &:hover {
    color: #e2e8f0;
  }
}

.empty-text {
  color: $color-text-placeholder;
  text-align: center;
  padding: $space-2xl;
}
</style>
