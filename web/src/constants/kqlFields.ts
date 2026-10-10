// 分析中心 KQL 自动补全的字段清单（对应 soc-ai-* 索引的 ai.* 字段）
// values 为枚举字段的可选值，插入时自动加引号与字段冒号

import { SOC_CATEGORY_COLORS } from './esFieldMapping'
import { ATTACK_RESULT_OPTIONS, THREAT_VERDICT_OPTIONS } from './alertFilters'

export interface KqlFieldDef {
  /** KQL 中使用的字段名 */
  name: string
  /** 中文别名，用于补全提示与检索 */
  alias: string
  /** 枚举字段的候选值 */
  values?: string[]
}

/** 按字段名取枚举候选值：日志中心复用分析中心的枚举口径（如告警类型/威胁判定） */
export function kqlEnumValues(fieldName: string): string[] | undefined {
  return KQL_FIELDS.find((f) => f.name === fieldName)?.values
}

export const KQL_FIELDS: KqlFieldDef[] = [
  { name: 'ai.alert_timestamp', alias: '原始日志时间' },
  { name: 'ai.source_ip', alias: '源IP' },
  { name: 'ai.source_port', alias: '源端口' },
  { name: 'ai.destination_ip', alias: '目的IP' },
  { name: 'ai.destination_port', alias: '目的端口' },
  { name: 'ai.protocol', alias: '协议' },
  {
    name: 'ai.soc_name',
    alias: '告警类型',
    values: Object.keys(SOC_CATEGORY_COLORS),
  },
  { name: 'ai.soc_category', alias: '告警分类' },
  { name: 'ai.alert_signature', alias: '威胁名' },
  { name: 'ai.alert_signature_id', alias: '规则ID' },
  { name: 'ai.confidence', alias: '可信度' },
  {
    name: 'ai.threat_verdict',
    alias: '威胁判定',
    values: THREAT_VERDICT_OPTIONS.map((o) => o.value),
  },
  {
    name: 'ai.attack_result',
    alias: '攻击结果',
    values: ATTACK_RESULT_OPTIONS.map((o) => o.value),
  },
  { name: 'ai.attack_stage', alias: '攻击阶段' },
  { name: 'ai.attack_technique', alias: '攻击手法' },
  { name: 'ai.mitre_id', alias: 'MITRE 编号' },
  { name: 'ai.payload', alias: '请求载荷' },
  { name: 'ai.response_body', alias: '响应内容' },
  { name: 'ai.http_url', alias: 'HTTP URL' },
  { name: 'ai.http_host', alias: 'HTTP Host' },
  { name: 'ai.http_method', alias: 'HTTP 方法' },
  { name: 'ai.http_status', alias: 'HTTP 状态码' },
  { name: 'ai.http_user_agent', alias: 'User-Agent' },
  { name: 'ai.tls_sni', alias: 'TLS SNI' },
  { name: 'ai.source_alert_id', alias: '原始日志ID' },
  { name: 'ai.analysis_source', alias: '分析来源' },
]
