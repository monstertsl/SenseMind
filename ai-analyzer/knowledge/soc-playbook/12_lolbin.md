# SOC 处置手册: 12_lolbin (LOLBin攻击)

## 适用告警

certutil、bitsadmin、mshta、rundll32、regsvr32、wmic 滥用
MITRE T1218

## 分析要点

### 判断是否误报
- **系统更新**：Windows Update 正常使用 bitsadmin 下载补丁
- **证书管理**：管理员正常使用 certutil 管理证书
- **软件安装**：正常使用 msiexec 安装软件
- **合法远程管理**：运维正常使用 wmic/PsExec

### 判断攻击是否成功
| LOLBin | 滥用特征 | 成功标志 |
|--------|---------|---------|
| certutil | `-urlcache -split -f http://` | 下载文件到本地 |
| bitsadmin | `/transfer` 下载到临时目录 | 文件下载完成 |
| mshta | 执行远程 `.hta` 文件 | 远程脚本执行 |
| rundll32 | 加载远程 DLL | DLL 执行 |
| regsvr32 | `/s /u /i:http://` 加载 .sct | 脚本执行 |
| wmic | `/node:REMOTE process call create` | 远程命令执行 |

### 关联分析
- **出站下载**：目标主机通过非浏览器进程下载文件
- **文件类型**：下载 `.hta`、`.sct`、`.dll`、`.msi` 等可执行文件类型
- **下载后行为**：下载完成后是否出现新的进程或 C2 连接
- **前置告警**：LOLBin 通常在 RCE 成功后使用，追溯漏洞利用告警

## 处置流程

1. **紧急**：确认 LOLBin 下载恶意文件 → 立即隔离主机、删除下载文件
2. **高**：可疑 LOLBin 下载 → 隔离主机、分析下载文件
3. **中**：LOLBin 远程执行 → 监控、确认是否为运维操作
4. **低**：误报（系统更新/证书管理） → 白名单
