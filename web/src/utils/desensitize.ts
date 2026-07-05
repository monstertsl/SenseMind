// 敏感信息脱敏：用于 Payload 与日志展示

// IP 脱敏：保留前两段，后两段替换为 *.  192.168.1.100 -> 192.168.*.*
export function maskIp(ip: string): string {
  if (!ip) return '-'
  const parts = ip.split('.')
  if (parts.length !== 4) return ip
  return `${parts[0]}.${parts[1]}.*.*`
}

// 关键字脱敏：手机号/身份证/邮箱/密码字段
export function maskSensitive(text: string): string {
  if (!text) return ''
  let result = text
  // 手机号 11位
  result = result.replace(/1[3-9]\d{9}/g, (m) => m.slice(0, 3) + '****' + m.slice(7))
  // 身份证 18位
  result = result.replace(/\b\d{17}[\dXx]\b/g, (m) => m.slice(0, 6) + '********' + m.slice(14))
  // 邮箱
  result = result.replace(/[\w.+-]+@[\w-]+\.[\w.-]+/g, (m) => {
    const [name, domain] = m.split('@')
    return name.slice(0, 2) + '***@' + domain
  })
  // password=xxx / pwd=xxx
  result = result.replace(/(password|passwd|pwd|secret|token)(\s*[=:]\s*)(['"]?)([^\s'"&]+)/gi, (_, k, sep, q, v) => {
    if (v.length <= 2) return `${k}${sep}${q}**`
    return `${k}${sep}${q}${v[0]}${'*'.repeat(Math.min(v.length - 2, 8))}${v[v.length - 1]}`
  })
  return result
}

// Payload 脱敏：对常见敏感字段做掩码
export function maskPayload(payload: string): string {
  if (!payload) return ''
  return maskSensitive(payload)
}
