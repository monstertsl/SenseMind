# SenseMind

> 基于 Suricata + Zeek + Elastic Stack + AI 的轻量级 SOC 安全运营平台，一键 Docker 化部署。

## 特性

- **双探针流量采集**：Suricata（告警/事件 + payload）与 Zeek（协议元数据）并行运行，Community ID 跨探针关联。
- **Elastic 全栈一体化**：Filebeat → Logstash（字段裁剪 + ECS 转换 + SOC 分类）→ Elasticsearch → Kibana。
- **SOC 14 大类分类**：Logstash 实时匹配 Suricata 告警，映射 MITRE ATT&CK 战术阶段，命中重点告警自动推送 AI。
- **6 阶段 AI 研判**：标准化 → 研判 → 动态关联查询 → RAG 知识增强 → 最终分析 → 规则生成，AI 自主决策，结构化输出。
- **三层联合查询**：Community ID 精确关联（同会话全量日志，跨 Suricata + Zeek 探针）+ 源/目的 IP 时间窗口关联（覆盖多连接、横向移动）+ IP 历史告警查询（24h），结果去重合并。
- **类语义检测引擎**：关键词匹配（13 类攻击特征）+ 递归解码（5 层 URL/HTML/Base64/Hex）+ 语法分析（SQL 注释清除、Shell 命令解析、路径规范化、XSS 标签检测），零 LLM 调用捕获编码绕过和变形攻击。
- **AI 自学习闭环**：确认攻击后自动生成 Suricata 规则写入 `local.rules` 并热加载，采用 HTTP sticky buffer 精确匹配 + 动态地址组，持续积累检测能力。
- **告警去重**：同一 `community_id` + `signature_id` 在时间窗口内只分析一次。
- **一键部署**：证书生成、密码引导、规则更新、数据视图创建、仪表板导入全流程自动化。

> **规划中**：接入客户端日志（syslog / Beats / 自定义推送），将主机层告警与网络流量关联，为 AI 研判提供更丰富的上下文，提升检测精度。

## 架构

```
   ┌───>Suricata eve.json / Zeek logs
   │               │
   │               │
   │    Filebeat (等待 Logstash 就绪)
   │               │
   │         Logstash 主管道
   规   字段裁剪 / ECS 转换 / SOC 分类
   则              │
   生         ┌────┴────┐
   成         │         │
   │       全量→ES   matched→AI推送管道
   │       soc-*       │
   │             AI 分析中心 (6阶段 Chain)
   └──────────────结果回写 ES (soc-ai-*)
                       │
                  Kibana 可视化
```

## 目录结构

```
SenseMind/
├── deploy.sh                    # 一键部署脚本
├── remove.sh                    # 彻底清理脚本
├── docker-compose.yml           # 全栈编排
├── certs/                       # ES SSL 证书（自动生成）
├── kibana/
│   └── sensemind-ai-dashboard.ndjson  # AI 研判仪表板（自动导入）
├── filebeat/filebeat.yml        # 采集配置
├── logstash/
│   ├── logstash.conf            # 主管道
│   ├── ai-push.conf             # AI 推送管道
│   └── soc_categories.json      # SOC 分类映射
└── ai-analyzer/
    ├── config.yaml              # LLM/ES/知识库/Suricata/去重 配置
    ├── knowledge/               # RAG 知识库（MITRE + SOC Playbook）
    └── app/                     # FastAPI + LangChain 6阶段 Chain
```
`ai-analyzer/knowledge`仅有基础RAG知识，需对其进行维护提高检测准确性

## 快速开始

### 环境要求

- Docker Engine + Docker Compose V2
- `curl`、`jq`、`unzip`、`openssl`、`ethtool`

### 部署

#### LLM 配置

编辑 `ai-analyzer/config.yaml`：支持 OpenAI、Ollama、vLLM 等 OpenAI 兼容后端。

```yaml
llm:
  api_key: "sk-xxx"
  base_url: "https://..."   # OpenAI 兼容接口
  model: "glm-5.2"          # 如果部署后需要修改模型执行: docker restart ai-analyzer
  temperature: 0.1
  max_tokens: 4000
  timeout: 60
```

#### 威胁情报配置（可选）

默认关闭，不影响部署。如需启用 IP/域名威胁情报查询，编辑 `ai-analyzer/config.yaml`：

```yaml
threat_intel:
  enabled: true                                        # 开启查询
  api_url: "http://10.0.0.1:8080/api/query?type={type}&value={value}"  # 接口地址，{type} 为 ip/domain，{value} 为查询值
  api_key: "your-api-key"                              # API Key，留空则不传
  api_key_in: "header"                                 # Key 传递方式: header 或 query
  api_key_name: "x-apikey"                             # Key 的 header/参数名
  timeout: 10                                          # 请求超时（秒）
  jq_filter: ""                                        # 响应字段提取（jq 语法），留空返回原始 JSON
```

> 必须显式设置 `enabled: true` 且 `api_url` 非空才会启用查询，默认关闭不产生任何请求。修改后执行 `docker restart ai-analyzer` 生效。


```bash
sudo bash deploy.sh <interface>   # 如 ens192、eth0
```

脚本自动完成：证书生成 → 密码引导 → 凭据持久化 → 全栈启动 → Suricata 规则更新 → 数据视图创建 → 仪表板导入。

### 访问

| 服务 | 地址 | 凭据 |
|------|------|------|
| Kibana | `http://<IP>:5601` | `elastic` / `.env` 中的 `ELASTIC_PASSWORD` |
| AI 仪表板 | `http://<IP>:5601/app/dashboards#/view/sensemind-ai-dashboard` | - |

```bash
cat .env | grep ELASTIC_PASSWORD
```

### 仪表板

SenseMind AI 研判仪表板包含：
- **指标卡**：AI 研判总数、受攻击目标数、攻击源 IP 数、平均可信度
- **统计图**：SOC 攻击分类分布、威胁判定分布、攻击结果分布
- **详情表**：原始时间、五元组、攻击类型、攻击名、可信度、溯源信息、处置建议、Payload

![AI 研判仪表板](demo-00.png)

![AI 研判仪表板](demo-01.png)

## SOC 分类

| 分类 | MITRE | 覆盖 |
|------|-------|------|
| 01 Web应用攻击 | T1190 | SQL注入/XSS/RCE/文件上传 |
| 02 身份认证攻击 | T1110 | 暴力破解/弱口令/撞库 |
| 03 扫描探测 | T1046 | 端口扫描/漏洞扫描器 |
| 04 漏洞利用 | T1068 | Log4j/Struts2/Fastjson |
| 05 恶意通信C2 | T1071 | 木马/Beacon/DGA/Cobalt Strike |
| 06 横向移动 | T1021 | SMB/RDP/PsExec |
| 07 数据泄露 | T1041 | 异常上传/数据外传 |
| 08 隧道通信 | T1572 | DNS隧道/ICMP隧道 |
| 09 DDoS | T1498 | SYN Flood/HTTP Flood |
| 10 主机攻击 | T1055 | 提权/凭据窃取 |
| 11 命令执行 | T1059 | PowerShell/Shell/宏 |
| 12 LOLBin | T1218 | certutil/bitsadmin/mshta |
| 13 信息泄露 | T1552 | .git/.env/源码泄露 |
| 14 恶意文件 | T1204 | 木马/勒索/RAT |

## 常用操作

```bash
# 更新 Suricata 规则
sudo docker exec --user suricata suricata suricata-update -f

# 热加载规则
sudo docker exec suricata suricatasc -c reload-rules

# 查看 AI 生成的规则
cat /data/suricata/lib/rules/local.rules

# 重启 AI 分析中心（修改 config.yaml 后）
docker restart ai-analyzer

# 手动触发某条告警分析
curl -X POST http://localhost:9090/api/analyze/<doc_id>
```

## 彻底清理

```bash
sudo bash remove.sh
```

清理容器、网络、数据卷、本地数据与证书（不删除已下载镜像）。

## 技术栈

| 组件 | 版本 |
|------|------|
| Elasticsearch / Kibana / Logstash / Filebeat | 8.19.16 |
| Suricata / Zeek | latest |
| AI 分析中心 | Python 3.12 + LangChain + FastAPI |

## 贡献

欢迎提交Issue/PR