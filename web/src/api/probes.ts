import request from './request'

// 探针列表项（F16 设备管理）
export interface ProbeItem {
  probe_uid: string
  name: string
  site: string
  status: 'pending' | 'active' | 'revoked'
  token_state: string // '' | 待使用 | 已过期（仅 pending 且已签发 token 时有值）
  online: boolean
  registered_at: string | null
  registered_ip: string
  last_report_at: string | null
  cert_not_after: string | null
  // 健康上报（F7）：最近一次拉取请求携带的指标
  health: {
    cpu?: number // CPU 使用率 %
    mem?: number // 内存使用率 %
    disk?: number // 数据盘使用率 %
    rx_bps?: number // 下行字节每秒
    tx_bps?: number // 上行字节每秒
    drop_pct?: number // 网卡丢包率 %
    disk_used?: number // 数据盘已用字节（探针升级 agent 后上报）
    disk_total?: number // 数据盘总容量字节
  } | null
}

// token 生成结果（token 仅此一次返回）
export interface ProbeTokenResult {
  probe_uid: string
  name: string
  site: string
  token: string
  /** 中心 CA 公钥证书 SHA256 指纹：与 token 拼成 token@指纹 作为部署凭证 */
  ca_fingerprint: string
  expires_at: string
}

export function listProbes() {
  return request.get<unknown, ProbeItem[]>('/probes')
}

export function createProbeToken(payload: { name: string; site?: string; rebind_uid?: string }) {
  return request.post<unknown, ProbeTokenResult>('/probes/token', payload)
}

export function updateProbe(probeUid: string, payload: { name?: string; site?: string }) {
  return request.put<unknown, ProbeItem>(`/probes/${probeUid}`, payload)
}

export function revokeProbe(probeUid: string) {
  return request.post<unknown, ProbeItem>(`/probes/${probeUid}/revoke`)
}

export function deleteProbe(probeUid: string) {
  return request.delete<unknown, null>(`/probes/${probeUid}`)
}
