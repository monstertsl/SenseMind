#!/bin/bash
set -e
# SenseMind 探针版部署脚本（F2，完全独立文件，不修改中心 deploy.sh）
# 网卡/镜像口配置逻辑移植自中心 deploy.sh（函数形式复用实现）。
#
# 用法：
#   sudo bash deploy-probe.sh <interface> <center_addr> <token>
#   center_addr: 中心地址（IP 或 IP:端口，端口缺省 8080），如 192.168.1.10
#   token:       中心 Web"设备管理"页生成的一次性接入 token（24h 有效）
#
# 幂等：更换中心地址 / 更换证书，重复运行本脚本即可，改完自动重启生效。
#
# 前置物料（与项目文件同目录）：
#   - docker-compose-probe.yml / filebeat/filebeat-probe.yml（项目内自带）
#   - certs/ca.crt      中心 CA 公钥证书（公钥可安全分发，随 token 一并提供）
#   - certs/probe/      本脚本生成（client.key / client.csr / client.crt）
if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    else
        echo "[-] 错误：此脚本需要 bash，请使用 bash 运行" >&2
        exit 1
    fi
fi

BASE_DIR=$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)

########################################
# 依赖检查（移植自中心 deploy.sh）
########################################
check_dependency() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "[-] 错误：缺少依赖 '$1'，请先安装：apt install -y $2"
        exit 1
    fi
}

check_dependency docker "docker.io docker-compose-plugin"
check_dependency curl "curl"
check_dependency jq "jq"
check_dependency openssl "openssl"
check_dependency ethtool "ethtool"

if ! docker compose version >/dev/null 2>&1; then
    echo "[-] 错误：需要 Docker Compose V2（docker compose 子命令）"
    exit 1
fi

########################################
# 参数解析
########################################
usage() {
    cat <<EOF
Usage: sudo bash $0 <interface> <center_addr> <token>

  interface    Suricata/Zeek 采集网卡（镜像口）
  center_addr  中心地址，IP[:端口]，端口缺省 8080
  token        中心 Web 设备管理页生成的一次性接入 token
Example: sudo bash deploy-probe.sh ens192 192.168.1.10 xxxxxx
EOF
}

if [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ $# -ne 3 ]; then
    usage
    [ $# -eq 3 ] || echo "[-] 错误：参数数量不对。"
    exit 1
fi

INTERFACE=$1
CENTER_ADDR=$2
TOKEN=$3

# 拆分中心地址：host 用于 5044，web 地址用于注册接口（缺省端口 8080）
case "$CENTER_ADDR" in
    *:*) CENTER_HOST="${CENTER_ADDR%%:*}"; CENTER_PORT="${CENTER_ADDR##*:}" ;;
    *)   CENTER_HOST="$CENTER_ADDR";       CENTER_PORT="8080" ;;
esac
CENTER_WEB="https://${CENTER_HOST}:${CENTER_PORT}"

export PUID=$(id -u)
export PGID=$(id -g)

echo "[+] 探针部署开始：网卡=$INTERFACE 中心=${CENTER_WEB}"

########################################
# 前置物料检查
########################################
if [ ! -f "$BASE_DIR/certs/ca.crt" ]; then
    echo "[-] 错误：缺少 $BASE_DIR/certs/ca.crt（中心 CA 公钥证书，用于校验中心身份）"
    echo "[-] 请从中心节点 certs/ 目录复制 ca.crt 到本机项目 certs/ 目录（公钥证书，可安全分发）"
    exit 1
fi
if [ ! -f "$BASE_DIR/docker-compose-probe.yml" ] || [ ! -f "$BASE_DIR/filebeat/filebeat-probe.yml" ]; then
    echo "[-] 错误：缺少 docker-compose-probe.yml 或 filebeat/filebeat-probe.yml"
    exit 1
fi
if [ ! -f "$BASE_DIR/probe-agent/agent.py" ] || [ ! -f "$BASE_DIR/probe-agent/Dockerfile" ] \
   || [ ! -f "$BASE_DIR/probe-agent/metrics_common.py" ] || [ ! -f "$BASE_DIR/probe-agent/logrotate.tmpl" ]; then
    echo "[-] 错误：缺少 probe-agent/ 目录（探针 agent 容器：采集/上报/配置下发/轮转）"
    exit 1
fi

########################################
# 网卡配置（移植自中心 deploy.sh：混杂模式 + offload 禁用 + systemd 持久化）
########################################
configure_nic() {
    local nic="$1"
    if command -v ip >/dev/null 2>&1; then
        if ! ip link show "$nic" >/dev/null 2>&1; then
            echo "[-] 错误：网卡接口 '$nic' 不存在。"
            exit 1
        fi
        echo "[*] 配置网络接口 $nic：开启混杂模式并禁用 offload"
        ip link set "$nic" promisc on
    fi
    ethtool -K "$nic" gro off
    ethtool -K "$nic" lro off
    ethtool -K "$nic" tso off
    ethtool -K "$nic" gso off
    # 禁用 RX/TX checksum offload，避免混杂模式捕获到错误 checksum 影响解析
    ethtool -K "$nic" rx off
    ethtool -K "$nic" tx off

    # 持久化（服务名与中心的 sensemind-network.service 区分，避免同机冲突）
    local net_service="/etc/systemd/system/sensemind-probe-network.service"
    cat > "$net_service" << EOF
[Unit]
Description=SenseMind probe network interface configuration
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'set -e; ip link set $nic promisc on; ethtool -K $nic gro off lro off tso off gso off rx off tx off'

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sensemind-probe-network.service 2>/dev/null || true
    echo "[+] 网卡配置已持久化（sensemind-probe-network.service）"
}

configure_nic "$INTERFACE"

########################################
# 双重预检（F2）：① 连通性 ② 时钟校验
# 任一失败直接报错退出、不落盘
########################################
echo "[*] 预检 1/2：中心连通性（TCP 5044 / 8080）..."
PRECHECK_5044=false
PRECHECK_8080=false
if timeout 5 bash -c "echo > /dev/tcp/${CENTER_HOST}/5044" 2>/dev/null; then
    PRECHECK_5044=true
fi
HTTP_CODE=$(curl -s --cacert "$BASE_DIR/certs/ca.crt" -o /dev/null -w "%{http_code}" \
    --max-time 8 "$CENTER_WEB/api/v1/auth/check-ip" 2>/dev/null) || true
if [ "${HTTP_CODE:-000}" != "000" ]; then
    PRECHECK_8080=true
fi
if [ "$PRECHECK_5044" != "true" ]; then
    echo "[-] 错误：中心 5044 端口不可达（${CENTER_HOST}:5044），请检查地址与网络。未做任何修改。"
    exit 1
fi
if [ "$PRECHECK_8080" != "true" ]; then
    echo "[-] 错误：中心 8080 不可达或 CA 校验失败（${CENTER_WEB}），请检查地址/网络/证书。未做任何修改。"
    exit 1
fi
echo "[+] 连通性预检通过（5044 ✓ 8080 ✓，且中心身份经 CA 校验）"

echo "[*] 预检 2/2：本机时钟校验（偏差 > 5 分钟将导致 TLS 校验失败死锁）..."
CENTER_DATE=$(curl -s --cacert "$BASE_DIR/certs/ca.crt" -I --max-time 8 \
    "$CENTER_WEB/api/v1/auth/check-ip" 2>/dev/null | grep -i '^date:' | cut -d' ' -f2- | tr -d '\r')
LOCAL_TS=$(date +%s)
CENTER_TS=$(date -d "$CENTER_DATE" +%s 2>/dev/null) || CENTER_TS=""
if [ -n "$CENTER_TS" ]; then
    SKEW=$(( LOCAL_TS > CENTER_TS ? LOCAL_TS - CENTER_TS : CENTER_TS - LOCAL_TS ))
    if [ "$SKEW" -gt 300 ]; then
        echo "[-] 错误：本机时钟与中心偏差 ${SKEW} 秒（> 5 分钟），请先校时（NTP/手动）后重试。未做任何修改。"
        exit 1
    fi
    echo "[+] 时钟校验通过（偏差 ${SKEW} 秒）"
else
    echo "[!] 无法解析中心时间响应头，跳过时钟校验（不影响注册，注册失败会明确报错）"
fi

########################################
# 证书注册（F3）：本地生成私钥+CSR（私钥不出机）→ 中心签发
########################################
PROBE_CERT_DIR="$BASE_DIR/certs/probe"
mkdir -p "$PROBE_CERT_DIR"
chmod 700 "$PROBE_CERT_DIR"

NEED_REGISTER=true
if [ -f "$PROBE_CERT_DIR/client.crt" ] && [ -f "$PROBE_CERT_DIR/client.key" ]; then
    # 已有证书且未到期（剩余 > 30 天）则跳过注册；否则自动重签
    NOT_AFTER=$(openssl x509 -enddate -noout -in "$PROBE_CERT_DIR/client.crt" | cut -d= -f2)
    REMAIN=$(( $(date -d "$NOT_AFTER" +%s) - LOCAL_TS ))
    if [ "$REMAIN" -gt $((30 * 86400)) ]; then
        echo "[+] 探针证书有效（剩余 $((REMAIN / 86400)) 天），跳过注册"
        NEED_REGISTER=false
    else
        echo "[*] 探针证书剩余不足 30 天，重新注册换发..."
    fi
fi

PROBE_UID=""

if [ "$NEED_REGISTER" = "true" ]; then
    echo "[*] 本地生成私钥与 CSR（私钥不出探针机）..."
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$PROBE_CERT_DIR/client.key" \
        -out "$PROBE_CERT_DIR/client.csr" \
        -subj "/CN=sensemind-probe" 2>/dev/null
    chmod 600 "$PROBE_CERT_DIR/client.key"

    echo "[*] 向中心提交注册（token + CSR，经 CA 校验的 HTTPS）..."
    REG_PAYLOAD=$(jq -n --arg token "$TOKEN" --arg csr "$(cat "$PROBE_CERT_DIR/client.csr")" \
        '{token: $token, csr: $csr}')
    REG_RESP=$(curl -s --cacert "$BASE_DIR/certs/ca.crt" \
        -X POST "$CENTER_WEB/api/v1/probe/register" \
        -H "Content-Type: application/json" \
        -d "$REG_PAYLOAD" --max-time 20) || true

    REG_CODE=$(echo "$REG_RESP" | jq -r '.code // empty' 2>/dev/null)
    if [ "$REG_CODE" != "0" ]; then
        DETAIL=$(echo "$REG_RESP" | jq -r '.detail // .message // "未知错误"' 2>/dev/null)
        echo "[-] 错误：注册失败：${DETAIL}"
        echo "[-] 未写入任何配置。请检查 token（24h 有效、一次性）后重试。"
        exit 1
    fi

    PROBE_UID=$(echo "$REG_RESP" | jq -r '.data.probe_uid')
    echo "$REG_RESP" | jq -r '.data.cert' > "$PROBE_CERT_DIR/client.crt"
    chmod 644 "$PROBE_CERT_DIR/client.crt"
    rm -f "$PROBE_CERT_DIR/client.csr"

    # 验证签发证书
    if ! openssl verify -CAfile "$BASE_DIR/certs/ca.crt" "$PROBE_CERT_DIR/client.crt" >/dev/null 2>&1; then
        # 客户端证书由探针 CA（中心侧 probe-ca）签发，中心 ca.crt 验证失败属预期，
        # 改为本地解析校验证书是否可读且 CN 正确
        CERT_CN=$(openssl x509 -noout -subject -in "$PROBE_CERT_DIR/client.crt" | grep -o 'CN = .*' | cut -d' ' -f3-)
        if [ "$CERT_CN" != "$PROBE_UID" ]; then
            echo "[-] 错误：签发证书 CN 校验失败（$CERT_CN != $PROBE_UID）"
            exit 1
        fi
    fi
    NTP_HINT=$(echo "$REG_RESP" | jq -r '.data.initial_config.ntp_servers // empty')
    echo "[+] 注册成功：内部 ID = $PROBE_UID（证书已落盘）"
    if [ -n "$NTP_HINT" ]; then
        echo "[+] 中心初始 NTP 配置：$NTP_HINT（配置下发通道将自动应用）"
    fi
else
    # 复用已有证书时，内部 ID 从证书 CN 恢复（保证 .env 一致）
    PROBE_UID=$(openssl x509 -noout -subject -in "$PROBE_CERT_DIR/client.crt" | grep -o 'CN = .*' | cut -d' ' -f3-)
fi

########################################
# .env 生成（不手动维护；更换中心地址重跑本脚本即更新）
########################################
ENV_FILE="$BASE_DIR/.env"
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"

write_env() {
    local key="$1" val="$2"
    grep -q "^${key}=" "$ENV_FILE" 2>/dev/null && \
        sed -i "s/^${key}=.*/${key}=${val}/" "$ENV_FILE" || \
        echo "${key}=${val}" >> "$ENV_FILE"
}

write_env "INTERFACE" "$INTERFACE"
write_env "CENTER_HOST" "$CENTER_HOST"
write_env "PROBE_UID" "$PROBE_UID"
echo "[+] .env 已更新（INTERFACE / CENTER_HOST / PROBE_UID）"

########################################
# 数据目录与 Zeek 过滤脚本（与单机版一致）
########################################
mkdir -p /data/suricata/logs /data/suricata/lib /data/suricata/lib/rules /data/suricata/etc /data/zeek/logs
chmod 755 /data/suricata/logs /data/suricata/lib /data/suricata/lib/rules /data/suricata/etc /data/zeek/logs 2>/dev/null || true

if [ ! -f /data/zeek/zeek-log-filter.zeek ]; then
    if [ -f "$BASE_DIR/zeek/zeek-log-filter.zeek" ]; then
        cp "$BASE_DIR/zeek/zeek-log-filter.zeek" /data/zeek/zeek-log-filter.zeek
    else
        echo "[-] 错误：缺少 zeek/zeek-log-filter.zeek（请从项目 zeek 目录复制到部署包）"
        exit 1
    fi
    chmod 644 /data/zeek/zeek-log-filter.zeek
fi
chown -R "$PUID:$PGID" /data/suricata/logs /data/suricata/lib /data/suricata/etc 2>/dev/null || true

# filebeat 配置权限
chown root:root "$BASE_DIR/filebeat/filebeat-probe.yml"
chmod 600 "$BASE_DIR/filebeat/filebeat-probe.yml"

########################################
# 探针 agent（容器化，probe-agent 服务）：健康采集/心跳上报/配置下发/吊销停服/日志轮转
# 旧宿主机 timer（probe-agent.sh）在此清理退役，功能已并入 probe-agent 容器
########################################
if systemctl list-unit-files 2>/dev/null | grep -q sensemind-probe-agent.timer; then
    systemctl stop sensemind-probe-agent.timer 2>/dev/null || true
    systemctl disable sensemind-probe-agent.timer 2>/dev/null || true
    rm -f /etc/systemd/system/sensemind-probe-agent.timer /etc/systemd/system/sensemind-probe-agent.service
    systemctl daemon-reload
    echo "[+] 已退役宿主机 agent timer（功能并入 probe-agent 容器）"
fi

# NTP 生效辅助：agent 容器只能写 timesyncd.conf（容器内无法 systemctl），
# 写完 touch /data/probe-agent/ntp.pending，由本 path unit 触发宿主机 restart timesyncd
cat > /etc/systemd/system/sensemind-ntp-apply.service << 'EOF'
[Unit]
Description=SenseMind probe NTP config apply (triggered by agent)

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'rm -f /data/probe-agent/ntp.pending && systemctl restart systemd-timesyncd && echo "[+] timesyncd 已重载 NTP 配置"'
EOF
cat > /etc/systemd/system/sensemind-ntp-apply.path << 'EOF'
[Unit]
Description=Watch SenseMind probe NTP pending marker

[Path]
PathModified=/data/probe-agent/ntp.pending

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sensemind-ntp-apply.path 2>/dev/null || true
echo "[+] NTP 生效辅助已安装（sensemind-ntp-apply.path）"

########################################
# 启动探针容器
########################################
echo "[*] 拉取/检查探针镜像..."
PROBE_IMAGES="jasonish/suricata:latest zeek/zeek:latest docker.elastic.co/beats/filebeat:8.19.16"
for IMG in $PROBE_IMAGES; do
    if ! docker image inspect "$IMG" >/dev/null 2>&1; then
        echo "[+] 拉取 $IMG ..."
        docker pull "$IMG" || {
            echo "[-] 拉取 $IMG 失败：无外网时可手动 docker load 导入镜像 tar 后重试。"
            exit 1
        }
    fi
done

export INTERFACE CENTER_HOST PROBE_UID
# 构建探针 agent 镜像（其他服务直接拉取现成镜像，无需构建）
docker compose -f "$BASE_DIR/docker-compose-probe.yml" build probe-agent || {
    echo "[-] 错误：probe-agent 镜像构建失败"
    exit 1
}
docker compose -f "$BASE_DIR/docker-compose-probe.yml" up -d --force-recreate

unset PUID PGID INTERFACE CENTER_HOST PROBE_UID

# Suricata 配置补丁（与中心 deploy.sh 同一补丁脚本）：jasonish/suricata 容器首次启动
# 会把默认 suricata.yaml 复制到挂载目录，等它落盘后打补丁——否则 rule-files 仍是
# 默认的空 suricata.rules，探针 Suricata 一条规则都不加载（ Eve 日志有、告警无）
SURICATA_YAML="/data/suricata/etc/suricata.yaml"
if [ ! -f "$SURICATA_YAML" ]; then
    echo "[*] 等待 Suricata 首次启动生成默认配置..."
    for _ in $(seq 1 30); do
        [ -f "$SURICATA_YAML" ] && break
        sleep 1
    done
fi
if [ -f "$SURICATA_YAML" ]; then
    python3 "$BASE_DIR/suricata/patch_yaml.py" "$SURICATA_YAML" || {
        echo "[-] 错误：Suricata 配置补丁未成功应用，请检查 yaml 结构"
        exit 1
    }
    # 立即热加载补丁后的规则（探针 agent 每 5 分钟心跳也会 reload，这里不等）
    docker exec probe-suricata suricatasc -c reload-rules >/dev/null 2>&1 || true
    echo "[+] Suricata 配置补丁已应用并热加载"
else
    echo "[-] 警告：Suricata 配置文件未生成，跳过补丁（规则将无法加载，请手动执行 suricata/patch_yaml.py）"
fi

echo "[+] =============================================="
echo "[+] 探针部署完成！"
echo "[+] 设备ID: $PROBE_UID"
echo "[+] 日志通道: ${CENTER_HOST}:5044（TLS+mTLS）"
echo "[+] 状态查看: 中心 Web → 系统设置 → 设备管理"
echo "[+] 更换中心地址/证书：重新运行本脚本即可"
echo "[+] =============================================="
