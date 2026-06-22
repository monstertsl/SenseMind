# SenseMind

> 基于 Suricata + Zeek + Elastic Stack + AI 的轻量级 SOC 安全运营平台，一键 Docker 化部署。

SenseMind 将网络流量深度分析（Suricata IDS / Zeek）、日志聚合检索（Filebeat + Logstash + Elasticsearch + Kibana）与 AI 智能研判融为一体。提供各类日志接入能力，全流程自动化，排除人力这个最薄弱环节，自动优化策略，实现对未知风险攻击的发现告警。

## 特性

- **双探针流量采集**：Suricata（告警/事件 + payload）与 Zeek（协议元数据）并行运行，覆盖全量网络流量。
- **Community ID 跨探针关联**：Suricata 与 Zeek 均启用 Community ID，可基于 `community_id` 精确关联同一会话的全部日志。
- **Payload 可读化**：Suricata 开启 `payload-printable`（4KB 上限），告警/事件直接携带可读载荷片段，供 AI 分析无需回溯 PCAP。
- **Elastic 全栈一体化**：Filebeat 采集 → Logstash 字段裁剪与 ECS 转换 → Elasticsearch 存储 → Kibana 可视化。
- **SOC 重点安全检测分类**：Logstash 实时对 Suricata 告警进行多大类分类匹配，映射 MITRE ATT&CK 战术阶段，命中重点告警自动推送 AI 分析中心。
- **AI 研判分析中心**：基于 LangChain 确定性链，支持 OpenAI 兼容格式接口，适配在线或本地模型，对告警 + 关联日志综合研判，输出威胁判定、攻击阶段、影响范围与处置建议，结果回写 ES。
- **一键部署**：单条命令完成证书生成、密码引导、规则更新、数据视图创建全流程。

## 架构

```plaintext
                         Raw 日志层
                            |
        +-------------------+-------------------+
        |                                       |
 Suricata eve.json                       Zeek logs
(alert/http/dns/tls/file)          (conn/http/dns/ssl)
        |                                       |
        +-------------------+-------------------+
                            |
                        Filebeat
                            |
                       Beats 协议
                            |
               +------------+------------+
               |     Logstash 主管道     |
               |  字段裁剪 / ECS 转换    |
               |  SOC 分类匹配 (soc.*)  |
               +------------+------------+
                            |
              +-------------+-------------+
              |                           |
      全量告警 → ES               matched=true → AI 推送管道
      (soc-* 索引)                (独立 pipeline，互不干扰)
              |                           |
              |                    HTTP POST 推送
              |                           v
              |                    AI 分析中心
              |                   (LangChain + LLM)
              |                           |
              |              +------------+------------+
              |              |                         |
              |        ES 关联日志查询         LangChain 确定性分析链
              |       (community_id 精确)      威胁研判/攻击链还原
              |       (IP+时间窗口 回退)       攻击结果/处置建议
              |              |                         |
              |              +------------+------------+
              |                           |
              |                   结果回写 ES
              |                  (soc-ai-* 索引)
              |                           |
              +-------------+-------------+
                            |
                    Kibana 可视化
                 soc-* / soc-ai-* 数据视图
                 SOC 运营 / 告警研判 / 攻击溯源
```

## 目录结构

```
SenseMind/
├── deploy.sh                # 一键部署脚本
├── docker-compose.yml       # 全栈编排（ES/Kibana/Logstash/Filebeat/Suricata/Zeek/AI分析中心）
├── certs/                   # ES SSL 证书（部署时自动生成，10 年有效期）
├── filebeat/
│   └── filebeat.yml         # Filebeat 采集配置
├── logstash/
│   ├── logstash.yml         # Logstash 配置
│   ├── pipelines.yml        # 多 pipeline 编排（主管道 + AI推送管道）
│   ├── logstash.conf        # 主管道：字段裁剪 + ECS 转换 + SOC分类
│   ├── ai-push.conf         # AI推送管道：独立推送 matched 告警到 AI 分析中心
│   └── soc_categories.json  # SOC 分类映射字典
├── ai-analyzer/             # AI 研判分析中心（LangChain + OpenAI兼容接口）
│   ├── Dockerfile           # AI 分析中心容器构建
│   ├── requirements.txt     # Python 依赖
│   ├── config.yaml          # LLM/ES/Webhook 配置（key、base_url、model）
│   └── app/
│       ├── main.py          # FastAPI Webhook 服务
│       ├── analyzer.py      # LangChain 确定性分析链
│       ├── es_client.py     # ES 关联查询 + 结果回写
│       ├── prompts.py       # 分析提示词模板
│       └── config.py        # 配置加载
└── remove.sh                # 彻底清理脚本
```

## 快速开始

### 环境要求

- Docker Engine + Docker Compose V2（`docker compose` 子命令）
- `curl`、`jq`、`unzip`、`ethtool`、`openssl`

### 一键部署

```bash
# <interface> 替换为监听网卡，如 ens192、eth0
sudo bash deploy.sh <interface>
```

部署脚本会自动完成：
1. 网卡开启混杂模式并禁用 GRO/LRO/TSO/GSO offload
2. 检查镜像（本地已有则跳过联网校验，缺失才拉取）
3. 生成 ES SSL 证书（CA + 节点证书，10 年有效期）
4. 生成 Kibana 加密密钥并持久化到 `.env`
5. 启动 Elasticsearch 并以 `ELASTIC_PASSWORD` 引导密码
6. 申请 Kibana Service Token 与 Logstash API Key
7. 拉起全栈并更新 Suricata 规则
8. 创建 Kibana 数据视图 `soc-*` 和 `soc-ai-*`

### 访问 Kibana

- 地址：`http://<服务器IP>:5601`
- 账号：`elastic`
- 密码：见 `.env` 中的 `ELASTIC_PASSWORD`

```bash
cat .env | grep ELASTIC_PASSWORD
```

### 查询日志

在 Kibana → Discover 中使用 KQL。

#### 原始告警（soc-* 数据视图）

```text
# 查看所有探针日志
event.module :"suricata" or event.module : "zeek"

# 仅查看告警
event.module :"suricata" and event.kind : "alert"

# 按 Community ID 关联同一会话
community_id : "<community_id_value>"

# 查询命中的 SOC 重点攻击告警（已分类）
soc.matched: true

# 按 SOC 分类筛选
soc.category: "01_web_attack"
soc.category: "04_exploit"

# 按 MITRE ATT&CK 技术编号筛选
soc.mitre_id: "T1190"
```

#### AI 分析结果（soc-ai-* 数据视图）

```text
# 查看所有 AI 分析结果
event.kind: "ai_analysis"

# 按威胁判定筛选
ai.threat_verdict: "确认威胁"
ai.threat_verdict: "可疑" and ai.confidence >= 0.8

# 按攻击结果筛选
ai.attack_result: "成功"

# 按五元组查询
ai.source_ip: "10.10.168.224"
ai.source_ip: "10.10.168.224" and ai.destination_ip: "10.10.168.128"
ai.source_ip: "10.10.168.224" and ai.source_port: 12345 and ai.destination_port: 5601

# 按 SOC 分类筛选
ai.soc_category: "01_web_attack"

# 按 MITRE 编号筛选
ai.mitre_id: "T1190"

# 通过原始告警 ID 关联（source_alert_id = 原始告警的 ES _id）
ai.source_alert_id: "<原始告警_id>"

# 通过 community_id 关联
ai.community_id: "<community_id_value>"
```

#### 跨索引关联溯源

```text
# 1. 在 soc-ai-* 中找到 AI 分析结果，记下 ai.source_alert_id
# 2. 切换到 soc-* 数据视图，按 _id 查原始告警
_id: "<ai.source_alert_id 的值>"

# 或用 community_id 在 soc-* 中查同会话所有日志
network.community_id: "<ai.community_id 的值>"
```

## 手动更新规则

```bash
docker exec --user suricata suricata suricata-update -f
```

## SOC 重点安全检测分类

Logstash 实时对每条 Suricata 告警进行 16 大类分类匹配，命中后打上 `soc.*` 标签并推送 AI 分析中心。

### 分类映射

| SOC 分类 | MITRE | 覆盖攻击类型 |
|---------|-------|------------|
| 01 Web应用攻击 | T1190 | SQL注入/XSS/RCE/XXE/SSTI/文件上传/目录遍历/Webshell |
| 02 身份认证攻击 | T1110 | 暴力破解/弱口令/默认密码/撞库/Session攻击 |
| 03 扫描探测行为 | T1046 | Nmap/Masscan/端口扫描/漏洞扫描器 |
| 04 漏洞利用攻击 | T1068 | Log4j/Struts2/Spring/Fastjson/Shiro/反序列化 |
| 05 恶意通信与C2 | T1071 | 木马通信/Beacon心跳/DGA域名/Tor/Cobalt Strike |
| 06 横向移动 | T1021 | SMB/RDP/WMI/PsExec/Pass The Hash |
| 07 数据泄露与外传 | T1041 | 异常上传/数据Dump/压缩文件外传 |
| 08 隧道通信 | T1572 | DNS隧道/ICMP隧道/SSH隧道 |
| 09 DDoS攻击 | T1498 | SYN Flood/UDP Flood/HTTP Flood/CC攻击 |
| 10 主机攻击 | T1055 | 持久化/提权/凭据窃取（LSASS/Mimikatz） |
| 11 命令与脚本执行 | T1059 | PowerShell/CMD/Shell/恶意脚本/宏 |
| 12 LOLBin攻击 | T1218 | certutil/bitsadmin/mshta/rundll32 |
| 13 信息泄露 | T1552 | .git/.env/源码/配置/密钥泄露 |
| 14 恶意文件与木马 | T1204 | 木马下载/Dropper/勒索软件/RAT |

### 匹配逻辑

1. **signature 关键词优先**：按 `alert.signature` 最长关键词匹配（如 `log4j RCE` 命中 `log4j` 而非 `rce`）
2. **category fallback**：signature 未命中时按 `alert.category` 精确匹配
3. 命中标记 `soc.matched=true`，携带 `soc.category`/`soc.name`/`soc.mitre_id`/`soc.stage`

详细映射规则见 `logstash/soc_categories.json`。

## AI 研判分析中心

### 工作流程

1. **告警分类**：Logstash 主管道对每条 Suricata 告警进行 SOC 分类匹配，命中重点告警标记 `soc.matched=true`
2. **双路输出**（独立 pipeline，互不干扰）：
   - **主管道**：全量告警写入 ES `soc-*` 索引（不受 AI 分析速度影响）
   - **AI 推送管道**：仅 `matched=true` 的告警通过 HTTP POST 推送到 AI 分析中心
3. **关联查询**：AI 分析中心收到告警后，从 ES 查询关联日志：
   - 优先用 `community_id` 精确关联同会话的 Zeek + Suricata 日志
   - 回退到 IP + 时间窗口（300秒）模糊关联
4. **AI 分析**：基于 LangChain 确定性链调用 LLM，输出威胁研判结果
5. **结果回写**：分析结果写入 ES `soc-ai-YYYY.MM.dd` 索引，供 Kibana 可视化

### AI 输出结构

每条分析结果写入 `soc-ai-*` 索引，所有字段在 `ai.*` 下：

#### 威胁研判

| 字段 | 说明 |
|------|------|
| `ai.threat_verdict` | 威胁判定：误报 / 可疑 / 确认威胁 |
| `ai.attack_result` | 攻击结果：成功 / 失败 / 未知 |
| `ai.confidence` | 置信度（0.0-1.0） |
| `ai.attack_technique` | 攻击手法描述 |
| `ai.attack_stage` | 攻击阶段（初始访问/执行/横向移动/数据外泄等） |
| `ai.impact_scope` | 影响范围评估 |
| `ai.attack_chain` | 攻击链还原 |
| `ai.handling_suggestion` | 处置建议（阻断措施/加固建议/监控方向） |
| `ai.reasoning` | 分析推理过程 |

#### 五元组信息

| 字段 | 说明 |
|------|------|
| `ai.source_ip` / `ai.source_port` | 源 IP / 源端口 |
| `ai.destination_ip` / `ai.destination_port` | 目的 IP / 目的端口 |
| `ai.protocol` | 传输协议（TCP/UDP） |
| `ai.community_id` | Community ID（跨探针会话关联） |

#### 告警信息

| 字段 | 说明 |
|------|------|
| `ai.alert_signature` / `ai.alert_signature_id` | Suricata 告警签名 / 规则 ID |
| `ai.alert_category` / `ai.alert_severity` | 告警分类 / 严重等级 |
| `ai.alert_timestamp` | 原始告警时间 |

#### HTTP/TLS 元数据

| 字段 | 说明 |
|------|------|
| `ai.http_method` / `ai.http_url` | HTTP 方法 / URL |
| `ai.http_host` / `ai.http_user_agent` | Host / User-Agent |
| `ai.tls_sni` | TLS SNI |

#### Payload 与溯源

| 字段 | 说明 |
|------|------|
| `ai.payload` | 攻击 Payload 原文（截断 4000 字符，供人工研判） |
| `ai.source_alert_id` | 原始告警的 ES `_id`（关联 `soc-*` 索引原始日志） |
| `ai.source_alert_index` | 原始告警所在的 ES 索引名 |

#### SOC 分类与 MITRE

| 字段 | 说明 |
|------|------|
| `ai.soc_category` / `ai.soc_name` | SOC 分类编号 / 分类名称 |
| `ai.mitre_id` | MITRE ATT&CK 技术编号 |
| `ai.attack_stage_tag` | 攻击阶段标签 |

#### 其他

| 字段 | 说明 |
|------|------|
| `ai.model` | 使用的 LLM 模型名称 |
| `ai.related_log_count` | 关联日志数量 |

### LLM 配置

AI 分析中心支持 OpenAI 兼容格式的 LLM 接口，通过 `ai-analyzer/config.yaml` 配置：

```yaml
llm:
  api_key: "sk-xxx"        # API Key
  base_url: "https://..."  # OpenAI 兼容 Base URL
  model: "glm-5.2"         # 模型名称
```

支持的典型后端：

| 场景 | base_url |
|------|----------|
| OpenAI | `https://api.openai.com/v1` |
| 本地 Ollama | `http://host.docker.internal:11434/v1` |
| 本地 vLLM | `http://host.docker.internal:8000/v1` |
| 其他 OpenAI 兼容服务 | 对应的 `/v1` 端点 |

### API 接口

| 端点 | 方法 | 说明 |
|------|------|------|
| `/health` | GET | 健康检查 |
| `/api/alert` | POST | 接收 Logstash 推送的告警（自动分析） |
| `/api/analyze/{doc_id}` | POST | 手动触发分析 ES 中的某条告警 |

## 彻底清理

清理容器、网络、数据卷、本地数据与证书（**不删除已下载的镜像**）：

```bash
sudo bash remove.sh
```

## 数据持久化

| 路径 | 内容 |
|------|------|
| Docker 卷 `esdata` | Elasticsearch 索引数据 |
| Docker 卷 `filebeat-data` | Filebeat 采集状态（registry） |
| `/data/suricata/logs` | Suricata eve.json 等日志 |
| `/data/suricata/lib` | Suricata 规则库 |
| `/data/suricata/etc` | Suricata 配置文件 |
| `/data/zeek/logs` | Zeek 各类日志（JSON 格式） |
| `./certs/` | ES SSL 证书（CA + 节点证书） |
| `./.env` | 密码、Token、密钥（权限 600） |
| `./ai-analyzer/config.yaml` | AI 分析中心 LLM 配置 |

## 技术栈

| 组件 | 版本 | 作用 |
|------|------|------|
| Elasticsearch | 8.19.16 | 日志存储与检索 |
| Kibana | 8.19.16 | 可视化与 SOC 运营 |
| Logstash | 8.19.16 | 字段裁剪 + ECS 转换 + SOC 分类匹配 |
| Filebeat | 8.19.16 | 日志采集 |
| Suricata | latest | IDS/IPS 告警与事件 |
| Zeek | latest | 网络流量元数据分析 |
| AI 分析中心 | Python 3.12 | LangChain 确定性链 + FastAPI Webhook |

## 项目进度

### 已完成

- [x] **全栈容器化编排**：`docker-compose.yml` 整合 Elasticsearch、Kibana、Logstash、Filebeat、Suricata、Zeek、AI 分析中心七大组件。
- [x] **双探针流量采集**：Suricata（告警/事件 + payload）与 Zeek（协议元数据）并行接入。
- [x] **Elastic Stack 数据通路**：Filebeat 采集 → Logstash 字段裁剪与 ECS 转换 → Elasticsearch 存储 → Kibana 可视化，全链路打通。
- [x] **SSL 安全加固**：ES HTTP + Transport 双层 SSL，Kibana/Logstash 通过 CA 证书信任。
- [x] **凭据持久化**：`ELASTIC_PASSWORD`、`KIBANA_TOKEN`、`LOGSTASH_API_KEY`、Kibana 加密密钥写入 `.env`，重启不丢失。
- [x] **数据持久化**：ES 数据、Filebeat registry、Suricata/Zeek 日志与规则、证书全部持久化到宿主机或 Docker 卷。
- [x] **Kibana 数据视图自动创建**：部署完成后自动创建 `soc-*` 和 `soc-ai-*` 数据视图并设为默认。
- [x] **SOC 重点安全检测分类**：Logstash 实时对 Suricata 告警进行多大类分类匹配，映射 MITRE ATT&CK 战术阶段。
- [x] **双 Pipeline 独立架构**：ES 写入与 AI 推送分离为独立 pipeline，AI 分析慢不影响 ES 写入。
- [x] **AI 研判分析中心**：基于 LangChain 确定性链，FastAPI Webhook 接收 Logstash 推送的告警，关联日志查询，输出威胁研判结果回写 ES。
- [x] **完整溯源信息**：AI 分析结果包含五元组、Payload 原文、原始告警 ES `_id`、community_id，支持跨索引关联溯源。
- [x] **多 LLM 后端支持**：支持 OpenAI 兼容格式接口，适配在线或本地模型，通过配置文件切换。

### 规划中

- [ ] **定时任务主动分析**：内置定时任务主动轮询 ES，按时间窗口批量分析积压告警。
- [ ] **攻击链自动关联**：跨时间窗口的攻击链还原，识别同一攻击者的多阶段行为。
- [ ] **Kibana 仪表板**：预置 SOC 运营仪表板，可视化展示威胁分布、攻击趋势、AI 研判结果。
- [ ] **告警降噪**：基于 AI 分析结果的自动抑制规则，减少重复告警。
