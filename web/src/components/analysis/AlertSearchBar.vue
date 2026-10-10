<script setup lang="ts">
import { reactive, watch } from 'vue'
import { Search, RefreshLeft, Collection } from '@element-plus/icons-vue'
import KqlInput from '@/components/common/KqlInput.vue'
import {
  ALERT_FILTER_KEYS,
  ATTACK_RESULT_OPTIONS,
  THREAT_VERDICT_OPTIONS,
  parseExcludeInput,
} from '@/constants/alertFilters'
import type { AlertQuery, AggregationBucket } from '@/types'

const props = defineProps<{
  modelValue: AlertQuery
  socNameBuckets: AggregationBucket[]
}>()

const emit = defineEmits<{
  search: [filters: Partial<AlertQuery>]
  reset: []
  save: []
}>()

// 可信度筛选：比较符 3 选 1 + 一个阈值，与日志中心语义一致
type ConfidenceOp = 'gte' | 'eq' | 'lte'

const form = reactive({
  kql: '',
  source_ip: '',
  destination_ip: '',
  soc_name: [] as string[],
  threat_verdict: [] as string[],
  attack_result: [] as string[],
  alert_signature: '',
  confidence_op: 'gte' as ConfidenceOp,
  confidence_value: undefined as number | undefined,
})

function emitSearch() {
  // 搜索时把表单筛选值通过 search 事件传给父组件，由父组件应用到 query
  // 排除条件：值以 ! 或 ！ 开头（源IP/目的IP/威胁名）
  const filters: Partial<AlertQuery> = {
    kql: form.kql.trim() || undefined,
    source_ip: undefined,
    destination_ip: undefined,
    alert_signature: undefined,
    exclude_source_ip: undefined,
    exclude_destination_ip: undefined,
    exclude_alert_signature: undefined,
    soc_name: form.soc_name.length ? form.soc_name.join(',') : undefined,
    threat_verdict: form.threat_verdict.length ? form.threat_verdict.join(',') : undefined,
    attack_result: form.attack_result.length ? form.attack_result.join(',') : undefined,
    confidence: undefined,
    confidence_min: undefined,
    confidence_max: undefined,
  }

  // 可信度阈值：按比较符落到后端对应参数
  const confidence = form.confidence_value
  if (confidence !== undefined && confidence !== null) {
    if (form.confidence_op === 'eq') filters.confidence = confidence
    else if (form.confidence_op === 'lte') filters.confidence_max = confidence
    else filters.confidence_min = confidence
  }

  // 源IP
  const sip = parseExcludeInput(form.source_ip)
  if (sip.value) {
    if (sip.exclude) filters.exclude_source_ip = sip.value
    else filters.source_ip = sip.value
  }

  // 目的IP
  const dip = parseExcludeInput(form.destination_ip)
  if (dip.value) {
    if (dip.exclude) filters.exclude_destination_ip = dip.value
    else filters.destination_ip = dip.value
  }

  // 威胁名
  const sig = parseExcludeInput(form.alert_signature)
  if (sig.value) {
    if (sig.exclude) filters.exclude_alert_signature = sig.value
    else filters.alert_signature = sig.value
  }

  emit('search', filters)
}

function reset() {
  form.kql = ''
  form.source_ip = ''
  form.destination_ip = ''
  form.soc_name = []
  form.threat_verdict = []
  form.attack_result = []
  form.alert_signature = ''
  form.confidence_op = 'gte'
  form.confidence_value = undefined
  emit('reset')
}

/** 把 query 中的筛选条件回填到表单（含排除条件与多选值） */
function fillForm(q: AlertQuery) {
  form.kql = q.kql || ''
  form.source_ip = q.exclude_source_ip ? `！${q.exclude_source_ip}` : q.source_ip || ''
  form.destination_ip = q.exclude_destination_ip ? `！${q.exclude_destination_ip}` : q.destination_ip || ''
  form.alert_signature = q.exclude_alert_signature ? `！${q.exclude_alert_signature}` : q.alert_signature || ''
  form.soc_name = q.soc_name ? q.soc_name.split(',').filter(Boolean) : []
  form.threat_verdict = q.threat_verdict ? q.threat_verdict.split(',').filter(Boolean) : []
  form.attack_result = q.attack_result ? q.attack_result.split(',').filter(Boolean) : []
  // 可信度：由后端参数反推比较符
  if (q.confidence !== undefined && q.confidence !== null) {
    form.confidence_op = 'eq'
    form.confidence_value = q.confidence
  } else if (q.confidence_min !== undefined && q.confidence_min !== null) {
    form.confidence_op = 'gte'
    form.confidence_value = q.confidence_min
  } else if (q.confidence_max !== undefined && q.confidence_max !== null) {
    form.confidence_op = 'lte'
    form.confidence_value = q.confidence_max
  } else {
    form.confidence_op = 'gte'
    form.confidence_value = undefined
  }
}

// 外部筛选回填（跨页面跳转、应用检索快捷方式）：仅监听筛选字段，
// 避免翻页/排序改动 query 时覆盖用户未提交的输入
watch(
  () =>
    JSON.stringify(
      ALERT_FILTER_KEYS.map(
        (key) => (props.modelValue as unknown as Record<string, unknown>)[key] ?? null,
      ),
    ),
  () => fillForm(props.modelValue),
  { immediate: true },
)
</script>

<template>
  <div class="search-bar">
    <!-- 工具条：KQL 高级查询 + 操作按钮 -->
    <div class="search-toolbar">
      <KqlInput
        v-model="form.kql"
        placeholder='如：ai.threat_verdict: "确认威胁" AND ai.confidence: >=0.8'
        @enter="emitSearch"
      />
      <div class="search-actions">
        <el-button type="primary" @click="emitSearch">
          <el-icon><Search /></el-icon>搜索
        </el-button>
        <el-button title="重置" @click="reset">
          <el-icon><RefreshLeft /></el-icon>
        </el-button>
        <el-button title="保存检索" @click="emit('save')">
          <el-icon><Collection /></el-icon>
        </el-button>
      </div>
    </div>

    <!-- 检索条件：全部铺开显示，宽度不够时换行 -->
    <div class="search-fields">
      <div class="field">
        <label>源IP</label>
        <el-input
          v-model="form.source_ip"
          placeholder="精确匹配，！排除"
          clearable
          @keyup.enter="emitSearch"
        />
      </div>
      <div class="field">
        <label>目的IP</label>
        <el-input
          v-model="form.destination_ip"
          placeholder="精确匹配，！排除"
          clearable
          @keyup.enter="emitSearch"
        />
      </div>
      <div class="field">
        <label>告警类型</label>
        <el-select
          v-model="form.soc_name"
          multiple
          collapse-tags
          collapse-tags-tooltip
          placeholder="选择类型"
          style="width: 100%"
        >
          <el-option
            v-for="b in socNameBuckets"
            :key="b.key"
            :label="`${b.key} (${b.count})`"
            :value="b.key"
          />
        </el-select>
      </div>
      <div class="field">
        <label>威胁判定</label>
        <el-select
          v-model="form.threat_verdict"
          multiple
          collapse-tags
          collapse-tags-tooltip
          placeholder="选择判定"
          style="width: 100%"
        >
          <el-option
            v-for="opt in THREAT_VERDICT_OPTIONS"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
      </div>
      <div class="field">
        <label>攻击结果</label>
        <el-select
          v-model="form.attack_result"
          multiple
          collapse-tags
          collapse-tags-tooltip
          placeholder="选择结果"
          style="width: 100%"
        >
          <el-option
            v-for="opt in ATTACK_RESULT_OPTIONS"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
      </div>
      <div class="field field-confidence">
        <label>可信度</label>
        <div class="confidence-row">
          <el-select v-model="form.confidence_op" class="confidence-op">
            <el-option label="≥" value="gte" />
            <el-option label="=" value="eq" />
            <el-option label="≤" value="lte" />
          </el-select>
          <el-input-number
            v-model="form.confidence_value"
            class="confidence-value"
            :min="0"
            :max="1"
            :step="0.05"
            :precision="2"
            :controls="false"
            placeholder="0-1"
          />
        </div>
      </div>
      <div class="field field-lg">
        <label>威胁名</label>
        <el-input
          v-model="form.alert_signature"
          placeholder="模糊匹配，！排除"
          clearable
          @keyup.enter="emitSearch"
        />
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
$field-label-height: 18px;
$field-label-gap: 4px;

.search-bar {
  background: $color-bg-elevated;
  border: 1px solid $color-border-light;
  border-radius: $radius-lg;
  padding: $space-lg $space-xl;
  display: flex;
  flex-direction: column;
  gap: $space-lg;
}

.search-toolbar {
  display: flex;
  align-items: center;
  gap: $space-md;
}

.search-fields {
  display: flex;
  gap: $space-lg;
  flex-wrap: wrap;
}

.field {
  display: flex;
  flex-direction: column;
  gap: $field-label-gap;
  min-width: 160px;
  flex: 1;
  label {
    font-size: 13px;
    line-height: $field-label-height;
    color: $color-text-primary;
    font-weight: 700;
  }
}

.field-lg {
  min-width: 220px;
  flex: 2;
}

.field-confidence {
  min-width: 168px;
  flex: 0 1 186px;
}

.confidence-row {
  display: flex;
  align-items: center;
  gap: 6px;

  .confidence-op {
    flex: 0 0 76px;
  }

  .confidence-value {
    flex: 1;
    min-width: 0;
  }

  :deep(.el-input__inner) {
    text-align: left;
  }
}

.search-actions {
  display: flex;
  gap: $space-sm;
  flex: 0 0 auto;
}
</style>
