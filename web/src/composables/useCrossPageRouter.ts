import { useRouter } from 'vue-router'
import { useLogExplorerStore } from '@/stores/logExplorer'

// 跨页面跳转工具：分析中心→日志中心，日志中心→分析中心
export function useCrossPageRouter() {
  const router = useRouter()
  const logStore = useLogExplorerStore()

  // 分析中心 source_alert_id（即原始日志 _id）→ 日志中心
  // 使用 _id 字段查询 soc-* 索引（_id 在 ES 中全局唯一）
  function goToLogExplorer(sourceAlertId: string) {
    logStore.setPendingSourceAlertId(sourceAlertId)
    router.push({
      path: '/log/explorer',
      query: { source_alert_id: sourceAlertId },
    })
  }

  // 日志中心 AI 研判标识 → 分析中心
  function goToAnalysisFromLog(docId?: string, sourceAlertId?: string) {
    const query: Record<string, string> = {}
    if (sourceAlertId) query.source_alert_id = sourceAlertId
    if (docId) query.doc_id = docId
    router.push({ path: '/analysis/alerts', query })
  }

  return { goToLogExplorer, goToAnalysisFromLog }
}
