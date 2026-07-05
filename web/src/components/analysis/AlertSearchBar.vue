<script setup lang="ts">
import { reactive, watch } from 'vue'
import { Search, RefreshLeft } from '@element-plus/icons-vue'
import type { AlertQuery, AggregationBucket } from '@/types'

const props = defineProps<{
  modelValue: AlertQuery
  socNameBuckets: AggregationBucket[]
}>()

const emit = defineEmits<{
  search: [filters: Partial<AlertQuery>]
  reset: []
}>()

const form = reactive({
  source_ip: '',
  destination_ip: '',
  soc_name: [] as string[],
  alert_signature: '',
})

function emitSearch() {
  // 搜索时把表单筛选值通过 search 事件传给父组件，由父组件应用到 query
  const filters: Partial<AlertQuery> = {
    source_ip: form.source_ip || undefined,
    destination_ip: form.destination_ip || undefined,
    soc_name: form.soc_name.length ? form.soc_name.join(',') : undefined,
    alert_signature: form.alert_signature || undefined,
  }
  emit('search', filters)
}

function reset() {
  form.source_ip = ''
  form.destination_ip = ''
  form.soc_name = []
  form.alert_signature = ''
  emit('reset')
}

// 外部筛选回填（跨页面跳转带入）
watch(
  () => props.modelValue,
  (q) => {
    if (q.source_ip) form.source_ip = q.source_ip
    if (q.destination_ip) form.destination_ip = q.destination_ip
    if (q.soc_name) form.soc_name = q.soc_name.split(',')
  },
  { immediate: true },
)
</script>

<template>
  <div class="search-bar">
    <div class="search-fields">
      <div class="field">
        <label>源IP</label>
        <el-input
          v-model="form.source_ip"
          placeholder="精确匹配，如 10.0.0.1"
          clearable
          @keyup.enter="emitSearch"
        />
      </div>
      <div class="field">
        <label>目的IP</label>
        <el-input
          v-model="form.destination_ip"
          placeholder="精确匹配"
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
      <div class="field field-lg">
        <label>威胁名</label>
        <el-input
          v-model="form.alert_signature"
          placeholder="模糊匹配"
          clearable
          @keyup.enter="emitSearch"
        />
      </div>
    </div>
    <div class="search-actions">
      <el-button type="primary" @click="emitSearch">
        <el-icon><Search /></el-icon>搜索
      </el-button>
      <el-button @click="reset">
        <el-icon><RefreshLeft /></el-icon>重置
      </el-button>
    </div>
  </div>
</template>

<style scoped lang="scss">
.search-bar {
  background: $color-bg-elevated;
  border: 1px solid $color-border-light;
  border-radius: $radius-lg;
  padding: $space-lg $space-xl;
  display: flex;
  gap: $space-lg;
  align-items: flex-end;
  flex-wrap: wrap;
}

.search-fields {
  display: flex;
  gap: $space-lg;
  flex: 1;
  flex-wrap: wrap;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 160px;
  flex: 1;
  label {
    font-size: 13px;
    color: $color-text-primary;
    font-weight: 700;
  }
}

.field-lg {
  min-width: 220px;
  flex: 2;
}

.search-actions {
  display: flex;
  gap: $space-sm;
}
</style>
