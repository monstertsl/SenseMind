<script setup lang="ts">
// KQL 输入框 + 光标处自动补全：先提示字段，输入冒号后提示该字段的枚举值
// 分析中心单行、日志中心多行共用，候选字段清单由调用方传入
import { nextTick, ref } from 'vue'
import type { InputInstance } from 'element-plus'
import { KQL_FIELDS, type KqlFieldDef } from '@/constants/kqlFields'

const props = withDefaults(
  defineProps<{
    modelValue: string
    placeholder?: string
    /** 候选字段清单，默认分析中心字段；日志中心传自己的字段表 */
    fields?: KqlFieldDef[]
    /** 日志中心的 KQL 用 textarea 承载多行 */
    type?: 'text' | 'textarea'
    rows?: number
  }>(),
  { fields: () => KQL_FIELDS, type: 'text', rows: 3 },
)

const emit = defineEmits<{
  'update:modelValue': [value: string]
  enter: []
}>()

interface Suggestion {
  label: string
  hint: string
  insert: string
}

const inputRef = ref<InputInstance | null>(null)
const open = ref(false)
const activeIndex = ref(0)
const suggestions = ref<Suggestion[]>([])
/** 候选项要替换的起始位置（相对输入框内容） */
const replaceStart = ref(0)
let blurTimer: ReturnType<typeof setTimeout> | null = null

type Ctx =
  | { mode: 'field'; partial: string; start: number }
  | { mode: 'value'; field: string; partial: string; start: number }

/** 原生输入元素：el-input 在 textarea 模式下暴露的引用不同，逐级兜底 */
function nativeEl(): HTMLInputElement | HTMLTextAreaElement | null {
  const inst = inputRef.value as unknown as {
    input?: HTMLInputElement
    textarea?: HTMLTextAreaElement
    $el?: HTMLElement
  } | null
  const fallback = inst?.$el?.querySelector('textarea, input') as
    | HTMLInputElement
    | HTMLTextAreaElement
    | null
  return inst?.input || inst?.textarea || fallback || null
}

/** 解析光标所在片段：字段上下文，或「字段: 值」的值上下文 */
function resolveContext(): Ctx | null {
  const el = nativeEl()
  if (!el) return null
  const pos = el.selectionStart ?? el.value.length
  const before = el.value.slice(0, pos)
  // 按逻辑操作符与括号切分，只取最后一段
  const segment = before.split(/(?:\b(?:AND|OR|NOT)\b|[()])/i).pop() ?? ''

  const valueMatch = segment.match(/([A-Za-z0-9_.]+)\s*:\s*([^:]*)$/)
  if (valueMatch) {
    return {
      mode: 'value',
      field: valueMatch[1],
      partial: valueMatch[2].replace(/^"/, '').trim(),
      start: pos - valueMatch[2].length,
    }
  }
  const partial = segment.replace(/^\s+/, '')
  return { mode: 'field', partial, start: pos - partial.length }
}

function buildSuggestions(ctx: Ctx): Suggestion[] {
  if (ctx.mode === 'field') {
    const partial = ctx.partial.toLowerCase()
    return props.fields
      .filter(
        (f) =>
          !partial ||
          f.name.toLowerCase().includes(partial) ||
          f.alias.toLowerCase().includes(partial),
      )
      .slice(0, 12)
      .map((f) => ({
        label: `${f.name}:`,
        hint: f.alias,
        insert: `${f.name}: `,
      }))
  }
  const field = props.fields.find((f) => f.name === ctx.field)
  if (!field?.values) return []
  const partial = ctx.partial.trim()
  return field.values
    .filter((v) => !partial || v.includes(partial))
    .map((v) => ({ label: v, hint: field.alias, insert: `"${v}"` }))
}

function refresh() {
  const ctx = resolveContext()
  if (!ctx) {
    open.value = false
    return
  }
  // 字段模式下空输入不弹（避免刚聚焦就糊一片）
  if (ctx.mode === 'field' && !ctx.partial) {
    open.value = false
    return
  }
  replaceStart.value = ctx.start
  suggestions.value = buildSuggestions(ctx)
  activeIndex.value = 0
  open.value = suggestions.value.length > 0
}

function onInput(value: string) {
  emit('update:modelValue', value)
  nextTick(refresh)
}

function apply(item: Suggestion) {
  const el = nativeEl()
  if (!el) return
  const pos = el.selectionStart ?? el.value.length
  const next = el.value.slice(0, replaceStart.value) + item.insert + el.value.slice(pos)
  emit('update:modelValue', next)
  const caret = replaceStart.value + item.insert.length
  open.value = false
  nextTick(() => {
    el.focus()
    el.setSelectionRange(caret, caret)
    // 插入字段后紧接着给该字段的值候选
    if (item.insert.endsWith(': ')) refresh()
  })
}

function onKeydown(e: KeyboardEvent) {
  if (open.value && suggestions.value.length) {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      activeIndex.value = (activeIndex.value + 1) % suggestions.value.length
      return
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      activeIndex.value = (activeIndex.value - 1 + suggestions.value.length) % suggestions.value.length
      return
    }
    if (e.key === 'Enter' || e.key === 'Tab') {
      e.preventDefault()
      apply(suggestions.value[activeIndex.value])
      return
    }
    if (e.key === 'Escape') {
      open.value = false
      return
    }
  }
  // textarea 下 Enter 是换行，不触发检索（日志中心另有「检索」按钮）
  if (e.key === 'Enter' && props.type !== 'textarea') emit('enter')
}

function onBlur() {
  // 延后关闭：点击候选项用 mousedown.prevent，不会被 blur 抢先
  blurTimer = setTimeout(() => {
    open.value = false
  }, 120)
}

function onFocus() {
  if (blurTimer) clearTimeout(blurTimer)
}
</script>

<template>
  <div class="kql-input">
    <el-input
      ref="inputRef"
      :model-value="props.modelValue"
      :type="props.type"
      :rows="props.rows"
      :placeholder="props.placeholder"
      clearable
      @update:model-value="onInput"
      @keydown="onKeydown"
      @focus="onFocus"
      @blur="onBlur"
    >
      <template #prefix>
        <span class="kql-prefix">KQL</span>
      </template>
    </el-input>

    <div v-if="open" class="kql-panel">
      <div
        v-for="(item, index) in suggestions"
        :key="`${item.insert}-${index}`"
        class="kql-item"
        :class="{ 'is-active': index === activeIndex }"
        @mousedown.prevent="apply(item)"
        @mouseenter="activeIndex = index"
      >
        <span class="kql-item-label">{{ item.label }}</span>
        <span class="kql-item-hint">{{ item.hint }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
.kql-input {
  position: relative;
  flex: 1;
  min-width: 0;
}

.kql-prefix {
  font-size: 11px;
  font-weight: 700;
  color: $color-text-secondary;
  letter-spacing: 0.5px;
}

.kql-panel {
  position: absolute;
  top: calc(100% + 4px);
  left: 0;
  right: 0;
  z-index: 3000;
  max-height: 264px;
  overflow-y: auto;
  padding: 4px 0;
  background: $color-bg-elevated;
  border: 1px solid $color-border-light;
  border-radius: $radius-md;
  box-shadow: $shadow-md;
}

.kql-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: $space-md;
  padding: 6px 12px;
  font-size: 12px;
  cursor: pointer;

  &.is-active {
    background: rgba(0, 92, 173, 0.06);
  }

  .kql-item-label {
    font-family: $font-mono;
    color: $color-text-primary;
    white-space: nowrap;
  }

  .kql-item-hint {
    color: $color-text-secondary;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
}
</style>
