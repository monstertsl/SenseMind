<p align="center"><img src="logo.png" alt="SenseMind" width="220"></p>

<h1 align="center">SenseMind</h1>

<p align="center"><strong>一个以 AI 为核心的轻量级 SOC 平台</strong><br>
自动从未命中攻击日志中挖掘低误报检测规则，通过持续积累检测规则实现自我进化，生生不息。</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License: MIT">
  <img src="https://img.shields.io/badge/docker-compose%20v2-2496ED?logo=docker&logoColor=white" alt="Docker Compose">
  <img src="https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white" alt="Python 3.12">
  <img src="https://img.shields.io/badge/Suricata%20%7C%20Zeek-latest-005571" alt="Suricata | Zeek">
  <img src="https://img.shields.io/badge/ELK-8.19.16-005571" alt="ELK 8.19.16">
  <img src="https://img.shields.io/github/last-commit/monstertsl/SenseMind?label=last%20commit" alt="Last commit">
</p>

<p align="center">
  <b>简体中文</b> | <a href="README_EN.md"><b>English</b></a>
</p>

---

开源检测栈（Suricata + ELK）在中小安全团队落地时的常见情况是：告警每天数百上千条，其中大部分为误报，人工跟进很难长期维持；存量规则依赖外部规则集更新，对自身环境中出现的真实攻击覆盖有限；而商业 SOC 平台的报价又超出这类团队的预算。真正发生入侵时，告警往往已经产生过，只是没有人看到。

SenseMind 针对的正是这一环节：告警先交由 AI 完成研判，确认攻击后自动生成低误报的检测规则并热加载生效，使同类攻击在后续被自动识别。检测能力不依赖外部规则集，而是随自身流量中出现的攻击持续积累。系统当前运行在生产流量中，规则池里的规则由系统自行生成与沉淀，不依赖人工逐条编写。

## 它如何工作

核心是一条闭环：**告警进入 AI 研判，研判确认攻击后生成规则并热加载，检测能力随之积累。**

1. **流量采集**：Suricata 输出告警与 payload，Zeek 输出协议元数据，两者通过 Community ID 关联。
2. **分类与投递**：Logstash 按 SOC 14 大类为告警打标，映射 MITRE ATT&CK 战术阶段，命中重点分类的告警自动推送至 AI 分析中心。
3. **AI 研判**：五个阶段依次执行——标准化 → 研判 → 动态关联查询 → RAG 知识增强 → 输出结论。关联查询包含 Community ID 精确关联、源/目的 IP 时间窗口关联、24 小时历史告警三个维度，跨 Suricata 与 Zeek 还原一次攻击的完整链路。
4. **规则生成与加载**：确认攻击后，AI 生成对应的 Suricata 规则（HTTP sticky buffer 精确匹配 + 动态地址组），写入规则池并热加载，无需重启引擎。
5. **规则沉淀**：仅保留低误报规则，检测能力持续积累。

本地生成规则示例：

```suricata
alert tcp any any -> any any (msg:"log4j：Log4Shell JNDI LDAP 注入远程代码执行漏洞利用"; flow:established,to_server; content:"${jndi:ldap://"; nocase; sid:93134; rev:1;)

alert http any any -> any any (msg:"auth bypass：Swagger UI API 文档未授权访问探测"; flow:established,to_server; http.uri; content:"swagger-ui"; nocase; sid:93152; rev:2;)
```

除规则命中的告警外，SenseMind 另有一个**语义检测引擎**：关键词匹配 + 5 层递归解码（URL / HTML / Base64 / Hex）+ 语法分析（SQL 注释清除、Shell 命令解析、路径规范化、XSS 标签检测）。该引擎不调用 LLM，用于捕获编码绕过与变形攻击。

<p align="center">
  <img src="demo-00.png" alt="AI 研判详情" width="100%">
  <br><sub>AI 研判详情：攻击确认、溯源分析、处置建议、Payload 命中高亮</sub>
</p>

<p align="center">
  <img src="demo-01.png" alt="监控中心" width="100%">
  <br><sub>监控中心：SOC 攻击分类、威胁判定分布、威胁分析来源</sub>
</p>

### 它不做什么

- 不采集主机日志。syslog / Beats 接入在规划中，当前仅覆盖网络流量。
- 不生成合规报表，不引入外部威胁情报订阅——检测能力来自自身流量中沉淀的规则。
- 不追求商业 SIEM 的全量功能覆盖，重点解决告警研判与规则积累两个环节。

## 快速开始

### 环境要求

- Docker Engine + Docker Compose V2
- `curl`、`jq`、`unzip`、`openssl`、`ethtool`
- 一台能收到待检测流量的 Linux 主机。**监听接口需要接镜像口（SPAN）、分光器或 TAP**。

### 配置参考（10 Gbps 内网镜像流量）

以下配置来自一套实际运行环境，可作为选型与容量规划的参考。

| 项目 | 配置 | 实测占用 |
|------|------|----------|
| CPU | Intel Xeon Silver 4210R（40 线程） | 平均约 13.4%（峰值 23.9%） |
| 内存 | 62 GiB | 平均约 41.1%（约合 26 GB，峰值 47.0%） |
| 系统盘 | 1.1 TB（单块 `sda`，LVM 卷组 `ubuntu-vg`） | 已用 49%，其中 Elasticsearch 数据卷约 367 GB |
| 监听网卡 | 10 Gb 全双工 | — |

磁盘占用主要来自原始日志（默认保留 7 天），可在「系统设置」中调小**原始日志保留天数**以压缩占用。

相关参数：Suricata af-packet 16 线程，flow 2 GiB / stream 4 GiB / reassembly 8 GiB memcap；Elasticsearch `-Xms2g -Xmx2g`、Logstash `-Xms4g -Xmx4g`（`docker-compose.yml` 内置）。

### 部署

```bash
git clone https://github.com/monstertsl/SenseMind.git
cd SenseMind
sudo bash deploy.sh <interface>   # 流量监听接口 如 eno1np0、ns192
```

`deploy.sh` 会自动完成网卡配置、证书生成、密码引导、规则更新与全栈启动。首次部署需要拉取镜像，耗时取决于网络。

### 访问

| 服务 | 地址 | 凭据 |
|------|------|------|
| SenseMind | `https://<IP>:8080` | `admin` / `.env` 中的 `ELASTIC_PASSWORD` |

```bash
cat .env | grep ELASTIC_PASSWORD
```

### 端口占用

| 端口 | 用途 | 暴露范围 |
|------|------|----------|
| 8080 | Web 控制台（HTTPS） | 所有网卡 |
| 5044 | Logstash Beats 输入 | 所有网卡 |
| 9090 | AI 分析中心 API | 仅 127.0.0.1 |
| 9200 | Elasticsearch | 仅 127.0.0.1 |
| 5432 | PostgreSQL | 仅 127.0.0.1 |

对外只需放行 8080；5044 仅在需要接收外部 Filebeat 推送时才放行。

### 配置 LLM

```
系统设置 > 集成配置 > LLM 模型
```

填写 OpenAI 兼容接口即可（vLLM / DashScope 均可）。

## 架构

```
   ┌───>Suricata eve.json / Zeek logs
   │               │
   │    Filebeat (等待 Logstash 就绪)
   │               │
   │         Logstash 主管道
   │    字段裁剪 / ECS 转换 / SOC 分类
   规              │
   则         ┌────┴────┐
   生         │         │
   成      全量→ES   matched→AI推送管道
   │       soc-*       │
   │          AI 分析中心 (5阶段 Chain)
   └──────────结果回写 ES (soc-ai-*)
                       │
                  SenseMind Web 可视化
```

## SOC 14 大类

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

## 目录结构

```
SenseMind/
├── deploy.sh                    # 一键部署脚本
├── remove.sh                    # 彻底清理脚本
├── docker-compose.yml           # 全栈编排
├── certs/                       # ES SSL 证书（自动生成）
├── filebeat/filebeat.yml        # 采集配置
├── logstash/
│   ├── logstash.conf            # 主管道
│   ├── ai-push.conf             # AI 推送管道
│   └── soc_categories.json      # SOC 分类映射
├── suricata/
│   ├── combined.rules           # 自定义规则
│   └── patch_yaml.py            # suricata.yaml 补丁脚本（幂等）
├── scripts/
│   └── suri_monitor.py          # 排错脚本：采样监控
├── ai-analyzer/
│   ├── config.yaml              # LLM/ES/知识库/Suricata/去重 配置
│   ├── knowledge/               # RAG 知识库（MITRE + SOC Playbook）
│   └── app/                     # FastAPI + LangChain 5阶段 Chain
└── web/                         # Vue 3 前端（监控中心/分析中心/日志中心/系统设置）
```

`ai-analyzer/knowledge` 仅有基础 RAG 知识，需对其进行维护提高检测准确性。

## 技术栈

| 组件 | 版本 |
|------|------|
| Elasticsearch / Logstash / Filebeat | 8.19.16 |
| Suricata / Zeek | latest |
| AI 分析中心 | Python 3.12 + LangChain + FastAPI |
| Web 前端 | Vue 3 + TypeScript + Pinia + Element Plus |
| 数据存储 | PostgreSQL 16 |

## 日常操作

```bash
# 更新 Suricata 规则
sudo docker exec --user suricata suricata suricata-update -f

# 热加载规则
sudo docker exec suricata suricatasc -c reload-rules

# 查看 AI 生成的规则
cat /data/suricata/lib/rules/local.rules

# 手动触发某条告警分析
curl -X POST http://localhost:9090/api/v1/analyze/<doc_id>
```

### 采样排错

```bash
# -i 指定监听接口（与部署时一致），默认 120s 采样一次
sudo python3 scripts/suri_monitor.py -i eno1np0

# 指定间隔与输出目录（默认 /tmp/sensemind-monitor/）
sudo python3 scripts/suri_monitor.py -i eno1np0 60 /tmp/suri-mon
```

输出目录下的 `suri_monitor.csv` 与同名 `.md`（可直接预览），采样间隔建议 ≥60s。

## 常见问题

以下情况均可通过命令行直接排查与处理。命令中 `sensemind-postgres` 和 `ai-analyzer` 为默认容器名。

### 告警有，但 AI 分析中心里是空的

告警的 `msg` 必须命中 `logstash/soc_categories.json` 中的分类关键词，才会带上 `soc.matched` 标记并推送至 AI 分析中心。自定义规则时需注意 `msg` 的命名。

### 查看当前 WEB 白名单

```bash
sudo docker exec sensemind-postgres psql -U postgres -d sensemind \
  -c "SELECT allowed_login_ips FROM system_config WHERE id=1;"
```

### 清空 WEB 白名单（允许所有 IP 访问）

```bash
sudo docker exec sensemind-postgres psql -U postgres -d sensemind \
  -c "UPDATE system_config SET allowed_login_ips='' WHERE id=1;"
```

### 或修改 WEB 白名单为正确的 IP

```bash
sudo docker exec sensemind-postgres psql -U postgres -d sensemind \
  -c "UPDATE system_config SET allowed_login_ips='IP地址' WHERE id=1;"
```

### 查看用户状态

```bash
docker exec -it sensemind-postgres psql -U postgres -d sensemind -c \
  "SELECT id, username, role, is_active, (totp_secret_encrypted IS NOT NULL) AS totp_enabled, failed_login_attempts, auth_mode, last_login_at FROM users;"
```

### 重置用户密码

将 `newpassword` 替换为你要设置的密码：

```bash
docker exec -i ai-analyzer python << 'EOF'
from app.core.auth import hash_password
from app.core.database import SessionLocal
from app.db_models.user import User
from sqlalchemy import update
h = hash_password('newpassword')
with SessionLocal() as db:
    result = db.execute(update(User).where(User.username=='admin').values(password_hash=h))
    db.commit()
    print(f'密码已重置，影响行数: {result.rowcount}')
EOF
```

### 解锁被禁用的账号

登录连续失败达到限制（默认 5 次）后账号会被自动禁用：

```bash
docker exec -it sensemind-postgres psql -U postgres -d sensemind -c \
  "UPDATE users SET failed_login_attempts=0, is_active=true WHERE username='admin';"
```

### 一键重置（密码 + 解锁 + 禁用 TOTP）

最常见的场景——忘记密码 + 账号被锁 + TOTP 丢失，一条命令全部搞定，密码重置为 `admin123`：

```bash
docker exec -i ai-analyzer python << 'EOF'
from app.core.auth import hash_password
from app.core.database import SessionLocal
from app.db_models.user import User
from sqlalchemy import update
h = hash_password('admin123')
with SessionLocal() as db:
    result = db.execute(update(User).where(User.username=='admin').values(
        password_hash=h, failed_login_attempts=0, is_active=True,
        totp_secret_encrypted=None, auth_mode='PASSWORD_ONLY'
    ))
    db.commit()
    print(f'已重置 admin 用户，影响行数: {result.rowcount}')
EOF
```

### 禁用 TOTP / 切换为纯密码模式

如果用户被设为 TOTP-only 或密码+TOTP 模式后丢失 TOTP 设备，可清除 TOTP 密钥并切回纯密码模式：

```bash
docker exec -it sensemind-postgres psql -U postgres -d sensemind -c \
  "UPDATE users SET totp_secret_encrypted=null, auth_mode='PASSWORD_ONLY' WHERE username='admin';"
```

### 创建新管理员

当所有管理员账号都无法恢复时，可直接创建一个新的（密码为 `admin123`）：

```bash
docker exec -i ai-analyzer python << 'EOF'
from app.core.auth import hash_password
from app.core.database import SessionLocal
from app.db_models.user import User
from sqlalchemy import select
h = hash_password('admin123')
with SessionLocal() as db:
    existing = db.execute(select(User).where(User.username=='newadmin')).scalar_one_or_none()
    if existing:
        print('用户 newadmin 已存在')
    else:
        db.add(User(
            username='newadmin', password_hash=h, role='admin',
            auth_mode='PASSWORD_ONLY', is_active=True, failed_login_attempts=0
        ))
        db.commit()
        print('已创建管理员 newadmin，密码: admin123')
EOF
```

### 启用/禁用用户

```bash
# 手动启用被禁用的用户
docker exec -it sensemind-postgres psql -U postgres -d sensemind -c \
  "UPDATE users SET is_active=true WHERE username='admin';"

# 手动禁用用户
docker exec -it sensemind-postgres psql -U postgres -d sensemind -c \
  "UPDATE users SET is_active=false WHERE username='test';"
```

## 彻底清理

```bash
sudo bash remove.sh
```

清理容器、网络、数据卷、本地数据与证书（不删除已下载镜像）。

## 贡献

欢迎提交 Issue / PR。反馈问题时，附上部署方式、监听接口类型（镜像口 / TAP）、Suricata 版本与相关日志，便于定位。

## 许可证

本项目采用 MIT License，详见 [LICENSE](LICENSE)。
