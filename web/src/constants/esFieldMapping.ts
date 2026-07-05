// ES 字段映射集中管理 —— 单一数据源，驱动表格列/搜索栏/条件构建器/Mapping校验
// 禁止组件内硬编码 ai.* 字段

export type FieldType = 'date' | 'keyword' | 'text' | 'long' | 'float' | 'ip' | 'boolean'
export type FieldGroup = '基础' | '网络' | 'AI研判'
export type Operator = 'eq' | 'ne' | 'like' | 'in' | 'gte' | 'lte' | 'range'

export interface TableColumnConfig {
  width: number
  align: 'left' | 'right' | 'center'
  hidden?: boolean
  sortable?: boolean
  copyable?: boolean
}

export interface EsFieldDef {
  key: string
  esField: string
  alias: string
  type: FieldType
  operators: Operator[]
  example: string
  group: FieldGroup
  tableColumn: TableColumnConfig
}

// 核心 12 字段（严格按规格顺序）
export const ES_FIELD_MAPPING: EsFieldDef[] = [
  {
    key: 'alert_timestamp',
    esField: 'ai.alert_timestamp',
    alias: '原始日志时间',
    type: 'date',
    operators: ['range', 'gte', 'lte'],
    example: '2026-07-03T10:00:00Z',
    group: '基础',
    tableColumn: { width: 180, align: 'left', sortable: true },
  },
  {
    key: 'source_ip',
    esField: 'ai.source_ip',
    alias: '源IP',
    type: 'ip',
    operators: ['eq', 'ne', 'in'],
    example: '192.168.1.100',
    group: '网络',
    tableColumn: { width: 140, align: 'left', copyable: true },
  },
  {
    key: 'source_port',
    esField: 'ai.source_port',
    alias: '源端口',
    type: 'long',
    operators: ['eq', 'range'],
    example: '54321',
    group: '网络',
    tableColumn: { width: 90, align: 'right' },
  },
  {
    key: 'destination_ip',
    esField: 'ai.destination_ip',
    alias: '目的IP',
    type: 'ip',
    operators: ['eq', 'ne', 'in'],
    example: '10.0.0.5',
    group: '网络',
    tableColumn: { width: 140, align: 'left', copyable: true },
  },
  {
    key: 'destination_port',
    esField: 'ai.destination_port',
    alias: '目的端口',
    type: 'long',
    operators: ['eq', 'range'],
    example: '443',
    group: '网络',
    tableColumn: { width: 90, align: 'right' },
  },
  {
    key: 'soc_name',
    esField: 'ai.soc_name',
    alias: '告警类型',
    type: 'keyword',
    operators: ['eq', 'in'],
    example: 'Web应用攻击',
    group: 'AI研判',
    tableColumn: { width: 130, align: 'left' },
  },
  {
    key: 'alert_signature',
    esField: 'ai.alert_signature',
    alias: '威胁名',
    type: 'text',
    operators: ['like'],
    example: 'ET POLICY Suspicious HTTP User-Agent',
    group: 'AI研判',
    tableColumn: { width: 240, align: 'left' },
  },
  {
    key: 'confidence',
    esField: 'ai.confidence',
    alias: '可信度',
    type: 'float',
    operators: ['eq', 'gte', 'lte', 'range'],
    example: '0.85',
    group: 'AI研判',
    tableColumn: { width: 90, align: 'left' },
  },
  {
    key: 'attack_chain',
    esField: 'ai.attack_chain',
    alias: '溯源分析',
    type: 'text',
    operators: ['like'],
    example: '攻击者通过SQL注入...',
    group: 'AI研判',
    tableColumn: { width: 120, align: 'left', hidden: true },
  },
  {
    key: 'handling_suggestion',
    esField: 'ai.handling_suggestion',
    alias: '处置建议',
    type: 'text',
    operators: ['like'],
    example: '1. 立即封禁源IP...',
    group: 'AI研判',
    tableColumn: { width: 120, align: 'left', hidden: true },
  },
  {
    key: 'payload',
    esField: 'ai.payload',
    alias: 'Payload',
    type: 'text',
    operators: ['like'],
    example: 'GET /admin?id=1 OR 1=1',
    group: 'AI研判',
    tableColumn: { width: 120, align: 'left' },
  },
  {
    key: 'source_alert_id',
    esField: 'ai.source_alert_id',
    alias: '原始日志ID',
    type: 'keyword',
    operators: ['eq'],
    example: 'abc123def456',
    group: '基础',
    tableColumn: { width: 150, align: 'left' },
  },
]

// 索引模式
export const AI_INDEX_PATTERN = 'soc-ai-*'
export const SOURCE_INDEX_PATTERN = 'soc-*'

// 启动时校验 Mapping：对比 ES 实际字段与本地定义
export function validateMapping(esFields: string[]): {
  valid: boolean
  missing: string[]
  present: string[]
} {
  const required = ES_FIELD_MAPPING.map((f) => f.esField)
  const present = required.filter((f) => esFields.includes(f) || esFields.includes(f.replace(/^ai\./, '')))
  const missing = required.filter((f) => !present.includes(f))
  return { valid: missing.length === 0, missing, present }
}

// 风险等级颜色映射（五级：健康/低/中/高/危急）
export const RISK_COLOR_MAP: Record<string, string> = {
  healthy: '#22c55e',
  low: '#3b82f6',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
}

export const RISK_LABEL_MAP: Record<string, string> = {
  healthy: '健康',
  low: '低危',
  medium: '中危',
  high: '高危',
  critical: '危急',
}

// SOC 14 大类配色
export const SOC_CATEGORY_COLORS: Record<string, string> = {
  'Web应用攻击': '#ef4444',
  '身份认证攻击': '#f97316',
  '扫描探测': '#eab308',
  '漏洞利用': '#ec4899',
  '恶意通信C2': '#8b5cf6',
  '横向移动': '#6366f1',
  '数据泄露': '#3b82f6',
  '隧道通信': '#0ea5e9',
  'DDoS': '#06b6d4',
  '主机攻击': '#10b981',
  '命令执行': '#84cc16',
  'LOLBin': '#a3e635',
  '信息泄露': '#f59e0b',
  '恶意文件': '#d946ef',
}

// 告警类型标签配色（按 SOC 大类）
export function getSocNameTagType(socName: string): 'danger' | 'warning' | 'success' | 'info' | 'primary' {
  const color = SOC_CATEGORY_COLORS[socName]
  if (!color) return 'info'
  if (['#ef4444', '#ec4899', '#d946ef'].includes(color)) return 'danger'
  if (['#f97316', '#eab308', '#f59e0b'].includes(color)) return 'warning'
  if (['#10b981', '#84cc16', '#a3e635'].includes(color)) return 'success'
  return 'primary'
}
