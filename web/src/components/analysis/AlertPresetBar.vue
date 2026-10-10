<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listAlertPresets, createAlertPreset, deleteAlertPreset } from '@/api/alertPreset'
import { ALERT_FILTER_KEYS, describeAlertFilters, pickAlertFilters } from '@/constants/alertFilters'
import type { AlertQuery, AlertSearchPreset } from '@/types'

// 当前检索条件：保存快捷方式时使用
const props = defineProps<{
  filters: Partial<AlertQuery>
}>()

const emit = defineEmits<{
  apply: [filters: Partial<AlertQuery>]
}>()

const presets = ref<AlertSearchPreset[]>([])
const loading = ref(false)

const activeFilters = computed(() => pickAlertFilters(props.filters))
const summaryText = computed(() => describeAlertFilters(activeFilters.value) || '（无筛选条件）')

async function fetchPresets() {
  loading.value = true
  try {
    const data = await listAlertPresets()
    presets.value = data.items || []
  } catch {
    // 静默失败：快捷方式不可用不应影响筛选与列表展示
    presets.value = []
  } finally {
    loading.value = false
  }
}

onMounted(fetchPresets)

/** 归一化筛选条件：用于判断两条快捷方式是否为同一检索条件 */
function normalize(filters: Partial<AlertQuery>): string {
  const picked = pickAlertFilters(filters)
  const raw = picked as Record<string, unknown>
  return JSON.stringify(ALERT_FILTER_KEYS.map((key) => [key, raw[key] ?? null]))
}

/** 当前检索条件与该快捷方式一致 → 标签高亮 */
function isActive(preset: AlertSearchPreset): boolean {
  return normalize(preset.filters || {}) === normalize(activeFilters.value)
}

/** 已存在的同条件快捷检索：同条件只允许一条，重复创建直接拦下 */
const duplicatePreset = computed<AlertSearchPreset | undefined>(() => {
  const current = normalize(activeFilters.value)
  return presets.value.find((p) => normalize(p.filters || {}) === current)
})

function presetTitle(preset: AlertSearchPreset): string {
  const summary = describeAlertFilters(preset.filters || {})
  return [preset.remark, summary].filter(Boolean).join(' / ') || preset.name
}

function handleApply(preset: AlertSearchPreset) {
  emit('apply', preset.filters || {})
}

async function handleDelete(preset: AlertSearchPreset) {
  try {
    await ElMessageBox.confirm(`确认删除快捷检索「${preset.name}」吗？`, '删除快捷方式', {
      type: 'warning',
      confirmButtonText: '删除',
      confirmButtonClass: 'el-button--danger',
    })
  } catch {
    return
  }
  try {
    await deleteAlertPreset(preset.id)
    ElMessage.success('已删除')
    await fetchPresets()
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '删除失败')
  }
}

// ---- 保存检索 ----
const saveDialogVisible = ref(false)
const saving = ref(false)
const saveForm = ref({ name: '', remark: '' })

function openSaveDialog() {
  if (!Object.keys(activeFilters.value).length) {
    ElMessage.warning('请检索后保存')
    return
  }
  saveForm.value = { name: '', remark: '' }
  saveDialogVisible.value = true
}

// 保存入口在搜索栏按钮组，由父页面调用
defineExpose({ openSaveDialog })

async function handleSave() {
  const name = saveForm.value.name.trim()
  if (!name) {
    ElMessage.warning('请输入快捷方式名称')
    return
  }
  if (duplicatePreset.value) {
    ElMessage.warning(`已存在相同检索条件的快捷方式「${duplicatePreset.value.name}」`)
    return
  }
  saving.value = true
  try {
    await createAlertPreset({
      name,
      remark: saveForm.value.remark.trim(),
      filters: activeFilters.value,
    })
    ElMessage.success('已保存快捷检索')
    saveDialogVisible.value = false
    await fetchPresets()
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail || e?.message || '保存失败')
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div class="preset-bar" v-loading="loading">
    <span class="preset-label">快捷检索</span>
    <div v-if="presets.length" class="preset-list">
      <el-tooltip
        v-for="p in presets"
        :key="p.id"
        :content="presetTitle(p)"
        placement="top"
        :show-after="200"
      >
        <el-tag
          class="preset-tag"
          :type="isActive(p) ? 'primary' : 'info'"
          :effect="isActive(p) ? 'dark' : 'plain'"
          closable
          @click="handleApply(p)"
          @close="handleDelete(p)"
        >
          {{ p.name }}
        </el-tag>
      </el-tooltip>
    </div>
    <span v-else-if="!loading" class="preset-empty">暂无快捷检索，点「保存检索」保存当前条件</span>
  </div>

  <el-dialog v-model="saveDialogVisible" title="保存检索" width="460px" class="preset-save-dialog">
    <el-form label-width="72px" label-position="left">
      <el-form-item label="名称">
        <el-input
          v-model="saveForm.name"
          placeholder="如：内网确认威胁"
          maxlength="100"
          @keyup.enter="handleSave"
        />
      </el-form-item>
      <el-form-item label="备注">
        <el-input v-model="saveForm.remark" placeholder="选填" maxlength="200" />
      </el-form-item>
    </el-form>
    <div class="preset-summary">
      <div class="summary-title">将保存当前检索条件</div>
      <div class="summary-text">{{ summaryText }}</div>
    </div>
    <div v-if="duplicatePreset" class="preset-dup">
      已存在相同检索条件的快捷方式「{{ duplicatePreset.name }}」，不能重复保存
    </div>
    <template #footer>
      <el-button @click="saveDialogVisible = false">取消</el-button>
      <el-button type="primary" :loading="saving" :disabled="!!duplicatePreset" @click="handleSave">
        保存
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped lang="scss">
.preset-bar {
  display: flex;
  align-items: flex-start;
  gap: $space-md;
  padding: $space-md $space-xl;
  background: $color-bg-elevated;
  border: 1px solid $color-border-light;
  border-radius: $radius-lg;
}

.preset-label {
  flex: 0 0 auto;
  font-size: 13px;
  line-height: 24px;
  font-weight: 700;
  color: $color-text-primary;
}

// 标签行：数量多时换行铺开，不做收缩/展开
.preset-list {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: $space-sm;
  min-width: 0;
}

.preset-tag {
  cursor: pointer;
}

.preset-empty {
  font-size: 13px;
  line-height: 24px;
  color: $color-text-placeholder;
}
</style>

<!-- 非 scoped：el-dialog teleport 到 body -->
<style lang="scss">
.preset-save-dialog {
  .preset-summary {
    margin: 0 0 $space-md 72px;
    padding: $space-sm $space-md;
    background: $color-bg-elevated;
    border: 1px solid $color-border-light;
    border-radius: $radius-md;
  }

  .summary-title {
    margin-bottom: 4px;
    font-size: 12px;
    color: $color-text-secondary;
  }

  .summary-text {
    font-size: 13px;
    color: $color-text-primary;
    word-break: break-all;
  }

  .preset-dup {
    margin: 0 0 $space-md 72px;
    font-size: 12px;
    color: $color-warning;
  }
}
</style>
