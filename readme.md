# SenseMind

> 基于 Suricata + Zeek + Elastic Stack + AI 的轻量级 SOC 安全运营平台，一键 Docker 化部署。

SenseMind 将网络流量深度分析（Suricata IDS / Zeek）、日志聚合检索（Filebeat + Logstash + Elasticsearch + Kibana）与 AI 智能研判融为一体。提供各类日志接入能力，全流程自动化，排除人力这个最薄弱环节，自动优化策略，实现对未知风险攻击的发现告警

## 特性

- **双探针流量采集**：Suricata（告警/事件 + payload）与 Zeek（协议元数据）并行运行，覆盖全量网络流量。
- **Community ID 跨探针关联**：Suricata 与 Zeek 均启用 Community ID，可基于 `community_id` 精确关联同一会话的全部日志。
- **Payload 可读化**：Suricata 开启 `payload-printable`（4KB 上限），告警/事件直接携带可读载荷片段，供 AI 分析无需回溯 PCAP。
- **Elastic 全栈一体化**：Filebeat 采集 → Logstash 字段裁剪与 ECS 转换 → Elasticsearch 存储 → Kibana 可视化。
- **AI 研判中间件**：基于 LangChain 确定性链，对告警 + 关联日志综合研判，输出威胁判定、攻击阶段、影响范围与处置建议，结果回写 ES。
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
                 +----------+----------+
                 |                     |
              字段裁剪    Logstash    ECS 转换
                 |                     |
                 +----------+----------+
                            |
                    Elasticsearch
                            |
        +-------------------+-------------------+
        |                                       |
     Kibana                              AI Agent
        |                                       |
    SOC 运营分析              community_id 关联分析
                          攻击链还原 / 风险研判
                          结果回写 ES (ai-analysis)
```

## 目录结构

```
SenseMind/
├── deploy.sh                # 一键部署脚本
├── docker-compose.yml       # 全栈编排（ES/Kibana/Logstash/Filebeat/Suricata/Zeek）
├── certs/                   # ES SSL 证书（部署时自动生成，10 年有效期）
├── filebeat/
│   └── filebeat.yml         # Filebeat 采集配置
└── logstash/
    ├── logstash.yml         # Logstash 配置
    └── logstash.conf        # 字段裁剪 + ECS 转换管道

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
8. 创建 Kibana 数据视图 `soc-*`

### 访问 Kibana

- 地址：`http://<服务器IP>:5601`
- 账号：`elastic`
- 密码：见 `.env` 中的 `ELASTIC_PASSWORD`

```bash
cat .env | grep ELASTIC_PASSWORD
```

### 查询日志

在 Kibana → Discover 中使用 KQL：

```text
# 查看所有探针日志
event.module :"suricata" or event.module : "zeek"

# 仅查看告警
event.module :"suricata" and event.kind : "alert"

# 按 Community ID 关联同一会话
community_id : "<community_id_value>"
```

## 规则更新

部署脚本默认拉取并启用全部免费 Suricata 规则源。手动更新：

```bash
docker exec --user suricata suricata suricata-update -f
```

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

## AI 研判能力

SenseMind 规划的 AI 中间件（基于 LangChain）实现：

1. **告警提取**：按时间、规则 ID、严重等级从 ES 筛选待分析告警。
2. **关联聚合**：优先用 `community_id` 精确拉取同会话的 Zeek + Suricata 日志；缺失时回退到 IP + 时间窗口模糊关联。
3. **数据清洗**：仅保留五元组、流量统计、签名、payload 等必需字段，截断超长字段，去重限条数。
4. **AI 分析**：输出威胁判定（误报/可疑/确认威胁）、攻击手法与阶段、影响范围、处置建议。
5. **结果回写**：分析结果写入 `ai-analysis` 索引，供 Kibana 可视化或触发二次告警。

检测分类覆盖 16 大类，详见 `SOC重点安全检测分类.md`，并映射 MITRE ATT&CK 战术阶段。

## 技术栈

| 组件 | 版本 | 作用 |
|------|------|------|
| Elasticsearch | 8.19.16 | 日志存储与检索 |
| Kibana | 8.19.16 | 可视化与 SOC 运营 |
| Logstash | 8.19.16 | 字段裁剪与 ECS 转换 |
| Filebeat | 8.19.16 | 日志采集 |
| Suricata | latest | IDS/IPS 告警与事件 |
| Zeek | latest | 网络流量元数据分析 |

## 项目进度

### 已完成

- [x] **全栈容器化编排**：`docker-compose.yml` 整合 Elasticsearch、Kibana、Logstash、Filebeat、Suricata、Zeek 六大组件。
- [x] **双探针流量采集**：Suricata（告警/事件 + payload）与 Zeek（协议元数据）并行接入。
- [x] **Elastic Stack 数据通路**：Filebeat 采集 → Logstash 字段裁剪与 ECS 转换 → Elasticsearch 存储 → Kibana 可视化，全链路打通。
- [x] **SSL 安全加固**：ES HTTP + Transport 双层 SSL，Kibana/Logstash 通过 CA 证书信任。
- [x] **凭据持久化**：`ELASTIC_PASSWORD`、`KIBANA_TOKEN`、`LOGSTASH_API_KEY`、Kibana 加密密钥写入 `.env`，重启不丢失。
- [x] **数据持久化**：ES 数据、Filebeat registry、Suricata/Zeek 日志与规则、证书全部持久化到宿主机或 Docker 卷。
- [x] **Kibana 数据视图自动创建**：部署完成后自动创建 `soc-*` 数据视图并设为默认。

### 规划中

- [ ] **AI 研判中间件**（基于 LangChain 确定性链）：
  - [ ] 告警提取：按时间、规则 ID、严重等级从 ES 筛选待分析 Suricata 告警。
  - [ ] AI 分析：关联日志聚合，输出威胁判定（误报/可疑/确认威胁）、攻击手法与阶段、影响范围评估、处置建议。
  - [ ] 结果回写：分析结果写入 `ai-analysis` 索引，供 Kibana 可视化或触发二次告警。
- [ ] **接入方式**：FastAPI Webhook 接收 Kibana 触发，或内置定时任务主动轮询 ES。
- [ ] **检测分类映射**：16 大类安全检测场景映射 MITRE ATT&CK 战术阶段
- [ ] **AI 容器化**：将 AI 中间件纳入 `docker-compose.yml`，通过环境变量管理 ES 地址、LLM Key 等。
