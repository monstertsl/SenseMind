<script setup lang="ts">
import { computed } from 'vue'
import { Plus, Delete, Search, RefreshLeft } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { storeToRefs } from 'pinia'
import { useLogExplorerStore } from '@/stores/logExplorer'
import type { LogFieldMapping } from '@/types'
import { ES_FIELD_MAPPING } from '@/constants/esFieldMapping'

const store = useLogExplorerStore()
const { conditions, kqlMode, kqlText, keyword, fieldMappings } = storeToRefs(store)

// 字段类型对应可用操作符
const OPERATOR_BY_TYPE: Record<string, { value: string; label: string }[]> = {
  keyword: [
    { value: 'eq', label: '等于' },
    { value: 'ne', label: '不等于' },
    { value: 'in', label: '包含其一' },
    { value: 'like', label: '通配匹配' },
  ],
  text: [
    { value: 'like', label: '模糊匹配' },
    { value: 'eq', label: '精确匹配' },
  ],
  ip: [
    { value: 'eq', label: '等于' },
    { value: 'ne', label: '不等于' },
    { value: 'in', label: '包含其一' },
  ],
  date: [
    { value: 'range', label: '时间范围' },
    { value: 'gte', label: '晚于' },
    { value: 'lte', label: '早于' },
  ],
  long: [
    { value: 'eq', label: '等于' },
    { value: 'gte', label: '≥' },
    { value: 'lte', label: '≤' },
    { value: 'range', label: '区间' },
  ],
  float: [
    { value: 'eq', label: '等于' },
    { value: 'gte', label: '≥' },
    { value: 'lte', label: '≤' },
  ],
  boolean: [{ value: 'eq', label: '等于' }],
}

// 字段白名单：只显示用户需要的字段
// 基础：仅 _id（原始日志ID）
// 网络：source.ip(源地址)、source.port、destination.ip(目的地址)、destination.port、network.community_id(community-id)
// AI研判：保留研判结论字段，排除与基础/网络分组重复的 5 个字段（ai.alert_timestamp / ai.source_ip / ai.source_port / ai.destination_ip / ai.destination_port）
// 其他分组（Suricata、其他等）全部隐藏
const ALLOWED_FIELDS: Record<string, string> = {
  '_id': '原始日志ID',
  'source.ip': '源地址',
  'source.port': '源端口',
  'destination.ip': '目的地址',
  'destination.port': '目的端口',
  'network.community_id': 'community-id',
}

// AI 研判分组中需隐藏的字段（与基础/网络分组语义重复）
const HIDDEN_AI_FIELDS = new Set([
  'ai.alert_timestamp',
  'ai.source_ip',
  'ai.source_port',
  'ai.destination_ip',
  'ai.destination_port',
  'ai.source_alert_id',
])

const allFields = computed(() => {
  const fromEs = fieldMappings.value
    .map((f) => ({
      name: f.name,
      alias: f.alias,
      type: f.type,
      example: f.example,
      group: f.group,
      available: f.available,
    }))
  const local = ES_FIELD_MAPPING
    .map((f) => ({
      name: f.esField,
      alias: f.alias,
      type: f.type,
      example: f.example,
      group: f.group,
      available: true,
    }))
  // _id 字段（ES 元数据，不在 mapping 中但始终可用）
  const idField = {
    name: '_id',
    alias: '原始日志ID',
    type: 'keyword' as const,
    example: 'abc123def456',
    group: '基础',
    available: true,
  }
  // 去重（按 name）
  const seen = new Set<string>()
  const merged = [idField, ...fromEs, ...local].filter((f) => {
    if (seen.has(f.name)) return false
    seen.add(f.name)
    return true
  })
  // 白名单过滤：
  //   - AI研判分组：保留全部，但排除 HIDDEN_AI_FIELDS 中与其他分组语义重复的字段
  //   - 其他分组：仅保留 ALLOWED_FIELDS 白名单中的字段
  return merged.filter((f) => {
    if (f.group === 'AI研判') return !HIDDEN_AI_FIELDS.has(f.name)
    return f.name in ALLOWED_FIELDS
  }).map((f) => {
    // 应用别名覆盖
    if (f.name in ALLOWED_FIELDS) {
      return { ...f, alias: ALLOWED_FIELDS[f.name] }
    }
    return f
  })
})

const groupedFields = computed(() => {
  const groups: Record<string, typeof allFields.value> = {}
  for (const f of allFields.value) {
    if (!groups[f.group]) groups[f.group] = []
    groups[f.group].push(f)
  }
  return groups
})

function getOperatorsForField(fieldName: string) {
  const field = allFields.value.find((f) => f.name === fieldName)
  if (!field) return OPERATOR_BY_TYPE.keyword
  return OPERATOR_BY_TYPE[field.type] || OPERATOR_BY_TYPE.keyword
}

function getFieldInfo(fieldName: string): LogFieldMapping | undefined {
  return allFields.value.find((f) => f.name === fieldName) as any
}

function onFieldChange(id: string, fieldName: string) {
  const ops = getOperatorsForField(fieldName)
  store.updateCondition(id, {
    field: fieldName,
    operator: ops[0]?.value || 'eq',
    value: '',
  })
}

function onPasteBatch(id: string, e: ClipboardEvent) {
  const text = e.clipboardData?.getData('text') || ''
  if (/[\n,;|\s]+/.test(text) && text.split(/[\n,;|\s]+/).filter(Boolean).length > 1) {
    e.preventDefault()
    const arr = text.split(/[\n,;|\s]+/).filter(Boolean)
    store.updateCondition(id, { value: arr })
  }
}

const emit = defineEmits<{ search: []; reset: [] }>()

function search() {
  // 关键字模糊匹配不能单独使用，必须配合其他条件
  const hasKeyword = keyword.value.trim()
  const hasConditions = conditions.value.some((c) => c.field && c.value !== '' && c.value !== undefined && c.value !== null)
  const hasKql = kqlMode.value && kqlText.value.trim()
  if (hasKeyword && !hasConditions && !hasKql) {
    ElMessage.warning('关键字模糊匹配需配合其他检索条件使用')
    return
  }
  emit('search')
}

function reset() {
  store.clearConditions()
  emit('reset')
}
</script>

<template>
  <div class="condition-builder">
    <div class="builder-header">
      <div class="builder-title">
        <el-icon><Search /></el-icon>
        <span>检索条件</span>
      </div>
      <div class="builder-actions">
        <el-radio-group v-model="kqlMode" size="default">
          <el-radio-button :value="false">可视化</el-radio-button>
          <el-radio-button :value="true">KQL 查询</el-radio-button>
        </el-radio-group>
      </div>
    </div>

    <!-- KQL 高级模式 -->
    <div v-if="kqlMode" class="kql-area">
      <el-input
        v-model="kqlText"
        type="textarea"
        :rows="3"
        placeholder="输入 KQL 查询，如：source.ip: 10.0.0.1 AND destination.port: 443"
      />
    </div>

    <!-- 可视化条件构建器 -->
    <div v-else class="conditions-area">
      <div v-if="!conditions.length" class="empty-conditions">
        <span>暂无条件，点击下方添加</span>
      </div>
      <div v-for="c in conditions" :key="c.id" class="condition-row">
        <!-- 字段下拉 -->
        <el-select
          :model-value="c.field"
          filterable
          placeholder="选择字段"
          class="field-select"
          @change="(v: string) => onFieldChange(c.id, v)"
        >
          <el-option-group v-for="(fields, group) in groupedFields" :key="group" :label="group">
            <el-option
              v-for="f in fields"
              :key="f.name"
              :label="`${f.alias} (${f.name})`"
              :value="f.name"
              :disabled="!f.available"
            >
              <span>{{ f.alias }}</span>
              <span class="field-name-hint">{{ f.name }}</span>
            </el-option>
          </el-option-group>
        </el-select>

        <!-- 操作符 -->
        <el-select
          :model-value="c.operator"
          class="op-select"
          @change="(v: string) => store.updateCondition(c.id, { operator: v })"
        >
          <el-option
            v-for="op in getOperatorsForField(c.field)"
            :key="op.value"
            :label="op.label"
            :value="op.value"
          />
        </el-select>

        <!-- 值输入 -->
        <el-input
          v-if="c.operator !== 'in'"
          :model-value="String(c.value)"
          class="value-input"
          :placeholder="getFieldInfo(c.field)?.example || '输入值'"
          @update:model-value="(v: string) => store.updateCondition(c.id, { value: v })"
          @paste="onPasteBatch(c.id, $event)"
        />
        <el-input
          v-else
          :model-value="Array.isArray(c.value) ? c.value.join(', ') : String(c.value)"
          class="value-input"
          placeholder="多个值用逗号/换行分隔"
          @paste="onPasteBatch(c.id, $event)"
        />

        <el-button
          text
          type="danger"
          class="remove-btn"
          @click="store.removeCondition(c.id)"
        >
          <el-icon><Delete /></el-icon>
        </el-button>
      </div>

      <div class="conditions-footer">
        <el-button class="add-btn" plain @click="store.addCondition()">
          <el-icon><Plus /></el-icon>添加条件
        </el-button>
        <el-input
          v-model="keyword"
          class="keyword-input"
          placeholder="关键字模糊匹配（需配合条件使用）"
          clearable
          :prefix-icon="Search"
          @keyup.enter="search"
        />
      </div>
    </div>

    <div class="builder-footer">
      <el-button type="primary" @click="search">
        <el-icon><Search /></el-icon>检索
      </el-button>
      <el-button @click="reset">
        <el-icon><RefreshLeft /></el-icon>重置
      </el-button>
    </div>
  </div>
</template>

<style scoped lang="scss">
.condition-builder {
  background: $color-bg-elevated;
  border: 1px solid $color-border-light;
  border-radius: $radius-lg;
  padding: $space-lg $space-xl;
}

.builder-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: $space-md;
}

.builder-title {
  display: flex;
  align-items: center;
  gap: $space-sm;
  font-size: 14px;
  font-weight: 600;
  color: $color-text-primary;
}

.builder-actions {
  display: flex;
  align-items: center;
  gap: $space-md;

  :deep(.el-radio-button__inner) {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    line-height: 1;
  }
}

.conditions-area {
  display: flex;
  flex-direction: column;
  gap: $space-sm;
}

.empty-conditions {
  padding: $space-lg;
  text-align: center;
  color: $color-text-placeholder;
  font-size: 13px;
  border: 1px dashed $color-border;
  border-radius: $radius-sm;
}

.condition-row {
  display: flex;
  gap: $space-sm;
  align-items: center;
}

.field-select {
  flex: 2;
}
.op-select {
  width: 130px;
  flex-shrink: 0;
}
.value-input {
  flex: 3;
}
.remove-btn {
  flex-shrink: 0;
}

.add-btn {
  width: fit-content;
  margin-top: $space-xs;
}

.kql-area {
  margin-bottom: $space-md;
}

.conditions-footer {
  display: flex;
  align-items: center;
  gap: $space-sm;
  margin-top: $space-sm;
}

.keyword-input {
  flex: 1;
}

.builder-footer {
  margin-top: $space-md;
  padding-top: $space-md;
  border-top: 1px solid $color-divider;
  display: flex;
  gap: $space-sm;
}

.field-name-hint {
  float: right;
  color: $color-text-placeholder;
  font-size: 11px;
  font-family: $font-mono;
}
</style>
