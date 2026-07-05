import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { LogCondition, LogFieldMapping } from '@/types'

// 日志中心状态：条件构建器 + 字段映射 + 列配置
export const useLogExplorerStore = defineStore('logExplorer', () => {
  const conditions = ref<LogCondition[]>([])
  const kqlMode = ref(false)
  const kqlText = ref('')
  const keyword = ref('')
  const fieldMappings = ref<LogFieldMapping[]>([])
  const visibleFields = ref<string[]>(['@timestamp', 'source.ip', 'destination.ip', 'event.dataset'])
  const columnWidths = ref<Record<string, number>>({})
  // 跨页面接收的 source_alert_id
  const pendingSourceAlertId = ref<string | null>(null)

  function addCondition(field = '', operator = 'eq', value: string | number | string[] = '') {
    conditions.value.push({
      id: `c_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      field,
      operator,
      value,
    })
  }

  function removeCondition(id: string) {
    conditions.value = conditions.value.filter((c) => c.id !== id)
  }

  function updateCondition(id: string, patch: Partial<LogCondition>) {
    const c = conditions.value.find((c) => c.id === id)
    if (c) Object.assign(c, patch)
  }

  function clearConditions() {
    conditions.value = []
    kqlText.value = ''
    keyword.value = ''
  }

  function setFieldMappings(fields: LogFieldMapping[]) {
    fieldMappings.value = fields
  }

  function setPendingSourceAlertId(id: string | null) {
    pendingSourceAlertId.value = id
  }

  function consumePendingSourceAlertId(): string | null {
    const id = pendingSourceAlertId.value
    pendingSourceAlertId.value = null
    return id
  }

  return {
    conditions,
    kqlMode,
    kqlText,
    keyword,
    fieldMappings,
    visibleFields,
    columnWidths,
    pendingSourceAlertId,
    addCondition,
    removeCondition,
    updateCondition,
    clearConditions,
    setFieldMappings,
    setPendingSourceAlertId,
    consumePendingSourceAlertId,
  }
})
