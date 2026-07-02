#!/bin/bash
set -e
# If the script was invoked with sh, re-exec under bash so bash-specific
# features like PIPESTATUS work correctly.
if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    else
        echo "[-] 错误：此脚本需要 bash，请使用 bash 运行：sudo bash $0 <interface>" >&2
        exit 1
    fi
fi
# Base directory of the script (absolute) to reliably locate .env when
# the script is executed via sudo or different working directories.
BASE_DIR=$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)

########################################
# 依赖检查（全新机器必需）
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
check_dependency unzip "unzip"
check_dependency openssl "openssl"

# 检查 docker compose 子命令（v2 插件）
if ! docker compose version >/dev/null 2>&1; then
    echo "[-] 错误：需要 Docker Compose V2（docker compose 子命令），请安装 docker-compose-plugin"
    exit 1
fi

echo "[+] 依赖检查通过"

usage() {
    cat <<EOF
Usage: $0 <interface>

You must specify the network interface to use with Suricata and Zeek.
Example: sudo sh ./deploy.sh ens192
EOF
}

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 0
fi

if [ -z "$1" ]; then
    echo "[-] 错误：必须指定网卡接口。"
    usage
    exit 1
fi

INTERFACE=$1
export INTERFACE

if command -v ip >/dev/null 2>&1; then
    if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
        echo "[-] 错误：网卡接口 '$INTERFACE' 不存在。"
        exit 1
    fi
    echo "[*] 0. 配置网络接口 $INTERFACE：开启混杂模式并禁用 offload"
    ip link set "$INTERFACE" promisc on
fi

if command -v ethtool >/dev/null 2>&1; then
    ethtool -K "$INTERFACE" gro off || true
    ethtool -K "$INTERFACE" lro off || true
    ethtool -K "$INTERFACE" tso off || true
    ethtool -K "$INTERFACE" gso off || true
fi

export PUID=$(id -u)
export PGID=$(id -g)

echo "[*] 检查 Docker 镜像..."

# docker compose pull 默认会联网核对所有镜像的远程 manifest，即便本地已有镜像，
# 在代理/离线环境下会导致校验失败并中断部署。这里改为：逐个检查本地是否已存在，
# 仅对本地缺失的镜像联网拉取，且失败时不中断整体流程；全部存在时静默跳过。
MISSING_IMAGES=""
TOTAL=0
while IFS= read -r IMG; do
    [ -z "$IMG" ] && continue
    TOTAL=$((TOTAL+1))
    if ! docker image inspect "$IMG" >/dev/null 2>&1; then
        MISSING_IMAGES="${MISSING_IMAGES}${IMG} "
    fi
done < <(docker compose config --images 2>/dev/null)

if [ -n "$MISSING_IMAGES" ]; then
    echo "[*] 本地缺失镜像，开始拉取: $MISSING_IMAGES"
    docker compose pull --ignore-pull-failures || \
        echo "[!] 部分镜像拉取失败，若本地已存在可继续，否则请检查网络/代理。"
else
    echo "[+] 镜像检测完成，全部已存在，跳过拉取"
fi

########################################
# 0.1 预生成 Elasticsearch SSL 证书
#     在启动任何容器之前生成，打破"先有ES还是先有证书"的循环依赖
########################################
CERTS_DIR="$BASE_DIR/certs"
if [ ! -f "$CERTS_DIR/elastic-certificates.p12" ] || [ ! -f "$CERTS_DIR/ca.crt" ]; then
    echo "[*] 生成 Elasticsearch SSL 证书（首次部署，有效期 10 年）..."
    mkdir -p "$CERTS_DIR"
    # ES 容器内 certutil 以 uid 1000(elasticsearch) 运行，而本目录由 sudo(root)
    # 创建且默认 755，uid 1000 无法写入会抛 AccessDeniedException。临时放开写权限。
    chmod 777 "$CERTS_DIR"

    # 1. 生成 CA（PEM 格式，便于 Kibana/Logstash 使用）
    #    -s/--silent 抑制 certutil 默认输出的大段帮助说明
    docker run --rm \
        -v "$CERTS_DIR:/certs" \
        --entrypoint /usr/share/elasticsearch/bin/elasticsearch-certutil \
        docker.elastic.co/elasticsearch/elasticsearch:8.19.16 \
        ca --pem --out /certs/ca.zip --days 3650 -s

    # 2. 解压 CA → certs/ca/ca.crt, certs/ca/ca.key
    if ! command -v unzip >/dev/null 2>&1; then
        echo "[-] 错误：需要 unzip 工具来解压证书，请先安装：apt install -y unzip"
        exit 1
    fi
    (cd "$CERTS_DIR" && unzip -oq ca.zip)

    # 3. 生成节点证书（PKCS12，用于 ES transport + HTTP SSL）
    docker run --rm \
        -v "$CERTS_DIR:/certs" \
        --entrypoint /usr/share/elasticsearch/bin/elasticsearch-certutil \
        docker.elastic.co/elasticsearch/elasticsearch:8.19.16 \
        cert --out /certs/elastic-certificates.p12 --pass "" \
        --ca-cert /certs/ca/ca.crt --ca-key /certs/ca/ca.key \
        --dns elasticsearch,localhost --ip 127.0.0.1 --days 3650 -s

    # 4. 将 ca.crt 复制到 certs 根目录，方便挂载
    cp "$CERTS_DIR/ca/ca.crt" "$CERTS_DIR/ca.crt"

    # 5. 清理临时文件
    rm -f "$CERTS_DIR/ca.zip"

    # 6. 设置权限
    chmod 644 "$CERTS_DIR/ca.crt" "$CERTS_DIR/elastic-certificates.p12"

    echo "[+] SSL 证书已生成: $CERTS_DIR/"
    echo "    - ca.crt                    (CA 证书，Kibana/Logstash 用)"
    echo "    - elastic-certificates.p12   (节点证书，ES 用)"
else
    echo "[+] SSL 证书已存在，跳过生成"
fi

########################################
# 0.2 清理残留容器
#     - 非全新部署时，上次失败可能残留容器，按服务名强制移除避免重名冲突
########################################
echo "[*] 清理可能残留的旧容器..."
docker compose down --remove-orphans 2>/dev/null >/dev/null || true
docker compose config --services 2>/dev/null | xargs -r docker rm -f >/dev/null 2>&1 || true

echo "[*] =============================================="

echo "[*] 1. 正在准备 Kibana 凭据..."
KEYS_RAW=$(docker run --rm docker.elastic.co/kibana/kibana:8.19.16 /usr/share/kibana/bin/kibana-encryption-keys generate -q 2>/dev/null)

export KIBANA_KEY_1=$(echo "$KEYS_RAW" | grep "encryptedSavedObjects" | awk '{print $2}' | tr -d '"\r\n')
export KIBANA_KEY_2=$(echo "$KEYS_RAW" | grep "reporting" | awk '{print $2}' | tr -d '"\r\n')
export KIBANA_KEY_3=$(echo "$KEYS_RAW" | grep "security" | awk '{print $2}' | tr -d '"\r\n')

if [ -z "$KIBANA_KEY_1" ] || [ -z "$KIBANA_KEY_2" ] || [ -z "$KIBANA_KEY_3" ]; then
    echo "[-] 错误：无法生成完整的 Kibana 加密密钥。"
    exit 1
fi

echo "[+] Kibana 加密密钥已生成，保持在当前 shell 环境中。"

# 持久化 Kibana 加密密钥到 .env，便于重启后继续使用
ENV_FILE="$BASE_DIR/.env"
EXISTING_ELASTIC_PASSWORD=""
EXISTING_LOGSTASH_API_KEY=""
EXISTING_KIBANA_TOKEN=""
if [ -f "$ENV_FILE" ]; then
    cp -f "$ENV_FILE" "${ENV_FILE}.bak" >/dev/null 2>&1 || true
    EXISTING_ELASTIC_PASSWORD=$(grep '^ELASTIC_PASSWORD=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)
    EXISTING_LOGSTASH_API_KEY=$(grep '^LOGSTASH_API_KEY=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)
    EXISTING_KIBANA_TOKEN=$(grep '^KIBANA_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)
fi
# 保留已有 .env 中的其他变量，仅更新 KIBANA_KEY_*
TMP_ENV_FILE="${ENV_FILE}.tmp"
grep -v '^KIBANA_KEY_[123]=' "$ENV_FILE" 2>/dev/null > "$TMP_ENV_FILE" || true
cat >> "$TMP_ENV_FILE" <<EOF
KIBANA_KEY_1=${KIBANA_KEY_1}
KIBANA_KEY_2=${KIBANA_KEY_2}
KIBANA_KEY_3=${KIBANA_KEY_3}
EOF
mv "$TMP_ENV_FILE" "$ENV_FILE"
if [ -n "$EXISTING_ELASTIC_PASSWORD" ] && ! grep -q '^ELASTIC_PASSWORD=' "$ENV_FILE" 2>/dev/null; then
    echo "ELASTIC_PASSWORD=${EXISTING_ELASTIC_PASSWORD}" >> "$ENV_FILE"
fi
if [ -n "$EXISTING_LOGSTASH_API_KEY" ] && ! grep -q '^LOGSTASH_API_KEY=' "$ENV_FILE" 2>/dev/null; then
    echo "LOGSTASH_API_KEY=${EXISTING_LOGSTASH_API_KEY}" >> "$ENV_FILE"
fi
if [ -n "$EXISTING_KIBANA_TOKEN" ] && ! grep -q '^KIBANA_TOKEN=' "$ENV_FILE" 2>/dev/null; then
    echo "KIBANA_TOKEN=${EXISTING_KIBANA_TOKEN}" >> "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"
echo "[+] 已将 Kibana 加密密钥持久化到 $ENV_FILE（权限 600）。"

# Ensure LOGSTASH_API_KEY exists to avoid docker-compose warnings when referenced
grep -q '^LOGSTASH_API_KEY=' "$ENV_FILE" 2>/dev/null || echo 'LOGSTASH_API_KEY=' >> "$ENV_FILE"

# 先导出空 Token，避免 docker compose 在只启动 elasticsearch 时解析 KIBANA_TOKEN 时报错。
export KIBANA_TOKEN=""

# 确保 filebeat.yml 的权限和所有者符合 Filebeat 要求
if [ -f "$BASE_DIR/filebeat/filebeat.yml" ]; then
    echo "[*] 修改 filebeat/filebeat.yml 权限，确保容器内 filebeat 可读取"
    chown root:root "$BASE_DIR/filebeat/filebeat.yml"
    chmod 600 "$BASE_DIR/filebeat/filebeat.yml"
fi

# 预创建宿主机 Suricata/Zeek 目录，以便日志、配置和规则持久化
mkdir -p /data/suricata/logs /data/suricata/lib /data/suricata/lib/rules /data/suricata/etc /data/zeek/logs
chmod 755 /data /data/suricata /data/zeek /data/suricata/logs /data/suricata/lib /data/suricata/lib/rules /data/suricata/etc /data/zeek/logs
chown -R "$PUID:$PGID" /data/suricata/logs /data/suricata/lib /data/suricata/lib/rules /data/suricata/etc

echo "[*] 2. 准备 elastic 密码并启动 Elasticsearch..."
# ES 8.x 首次启动（安全索引不存在）时，若设置了 ELASTIC_PASSWORD 环境变量，
# 会以此引导 elastic 用户密码；后续启动忽略该变量。
# 这避免了在 SSL 启用后 elasticsearch-reset-password CLI（需信任自签 CA）的麻烦。
EXISTING_PWD=$(grep '^ELASTIC_PASSWORD=' "$ENV_FILE" 2>/dev/null | cut -d= -f2-)
if [ -n "$EXISTING_PWD" ]; then
    ELASTIC_PASSWORD="$EXISTING_PWD"
    echo "[+] 使用已有 elastic 密码"
else
    ELASTIC_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)
    grep -v '^ELASTIC_PASSWORD=' "$ENV_FILE" 2>/dev/null > "${ENV_FILE}.tmp" || true
    echo "ELASTIC_PASSWORD=${ELASTIC_PASSWORD}" >> "${ENV_FILE}.tmp"
    mv "${ENV_FILE}.tmp" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "[+] elastic 密码已生成并写入 .env（ES 首次启动将以引导）"
fi
export ELASTIC_PASSWORD

docker compose up -d elasticsearch

echo "[*] 3. 等待 Elasticsearch 完全就绪..."
while true; do
    # 获取容器当前运行状态和健康状态
    STATUS=$(docker inspect --format='{{.State.Status}}' elasticsearch 2>/dev/null || echo "not_found")
    HEALTH=$(docker inspect --format='{{.State.Health.Status}}' elasticsearch 2>/dev/null || echo "none")

    if [ "$HEALTH" = "healthy" ]; then
        printf "\n[+] Elasticsearch 已进入 Healthy 状态!\n"
        break
    fi

    if [ "$STATUS" != "running" ]; then
        printf "\n[-] 错误：Elasticsearch 容器未能成功运行，当前状态：%s\n" "$STATUS"
        exit 1
    fi

    printf "."
    sleep 2
done

echo "[*] 3.1 验证 elastic 密码..."
# 密码已在启动 ES 前写入 .env，ES 首次启动时以 ELASTIC_PASSWORD 引导。
# 此处仅验证密码是否生效（curl -sk 跳过证书校验，从宿主机经端口映射访问）。
PWD_OK=false
for i in $(seq 1 20); do
    PWD_CHECK=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        -u "elastic:${ELASTIC_PASSWORD}" "https://localhost:9200/" 2>/dev/null) || true
    if [ "$PWD_CHECK" = "200" ]; then
        PWD_OK=true
        echo "[+] elastic 密码验证通过 (尝试 $i/20)"
        break
    fi
    printf "."
    sleep 3
done

if [ "$PWD_OK" != "true" ]; then
    printf "\n[-] 错误：elastic 密码验证失败（最后 HTTP 状态码: %s）\n" "${PWD_CHECK:-000}"
    echo "[-] 若复用旧数据卷(esdata)，ES 会忽略 ELASTIC_PASSWORD 而沿用旧密码。"
    echo "[-] 请清理后重试：sudo bash remove.sh && sudo bash deploy.sh $INTERFACE"
    exit 1
fi

echo "[*] 3.2 正在申请 Kibana 接入 Token..."
# 通过 REST API 创建 service token，避免 elasticsearch-service-tokens CLI 的 SSL 信任问题。
# 先删除可能存在的旧 token（幂等），再创建新 token。
curl -sk -u "elastic:${ELASTIC_PASSWORD}" -X DELETE \
    "https://localhost:9200/_security/service/elastic/kibana/credential/token/kibana-token" >/dev/null 2>&1 || true

TOKEN_RESP=$(curl -sk -u "elastic:${ELASTIC_PASSWORD}" -X POST \
    "https://localhost:9200/_security/service/elastic/kibana/credential/token/kibana-token" \
    -H "Content-Type: application/json" 2>/dev/null)
export KIBANA_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.token.value // empty' | tr -d '\r\n')

if [ -z "$KIBANA_TOKEN" ]; then
    echo "[-] 错误：无法创建 Kibana Service Token！ES 响应: $TOKEN_RESP"
    exit 1
fi

echo "[+] Kibana Token 已生成，保持在当前 shell 环境中。"

# 持久化 KIBANA_TOKEN 到 .env（更新或追加）
if [ -n "$KIBANA_TOKEN" ]; then
    ENV_FILE=${ENV_FILE:-$ENV_FILE}
    grep -v '^KIBANA_TOKEN=' "$ENV_FILE" 2>/dev/null > "${ENV_FILE}.tmp" || true
    echo "KIBANA_TOKEN=${KIBANA_TOKEN}" >> "${ENV_FILE}.tmp"
    mv "${ENV_FILE}.tmp" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "[+] 已将 Kibana Token 持久化到 $ENV_FILE（权限 600）。"
fi

echo "[*] 3.3 正在等待 Elasticsearch 安全模块完全就绪..."

# 使用脚本开头定义的 BASE_DIR 绝对路径加载环境变量
if [ ! -f "$BASE_DIR/.env" ]; then
    echo "[-] 致命错误：找不到 $BASE_DIR/.env"
    exit 1
fi
. "$BASE_DIR/.env"

# 显式检查密码变量
if [ -z "${ELASTIC_PASSWORD}" ]; then
    echo "[-] 致命错误：ELASTIC_PASSWORD 为空！.env 内容如下："
    grep "PASSWORD\|TOKEN\|KEY" "$BASE_DIR/.env" || true
    exit 1
fi

AUTH_READY=false
for i in $(seq 1 20); do
    # 分离 curl 执行与状态码提取，避免管道或子shell导致的 set -e 陷阱
    CURL_OUTPUT=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        -u "elastic:${ELASTIC_PASSWORD}" \
        "https://localhost:9200/_security/_authenticate" 2>/dev/null) || true
    
    AUTH_CODE="${CURL_OUTPUT:-000}"
    
    if [ "$AUTH_CODE" = "200" ]; then
        AUTH_READY=true
        echo "[+] Elasticsearch 安全模块已就绪 (尝试 $i/20)"
        break
    fi
    
    printf "."
    sleep 3
done

if [ "$AUTH_READY" != "true" ]; then
    echo ""
    echo "[-] 错误：Elasticsearch 安全模块在 60 秒内未就绪"
    echo "[-] 最后认证响应码: ${AUTH_CODE}"
    docker logs elasticsearch --tail 50 2>&1 | grep -iE "security|exception|error|authentication" || true
    exit 1
fi

echo "[*] 3.4 正在生成 logstash API Key..."

# 确保从 .env 读取到最新的密码
. "$ENV_FILE"

if [ -z "$ELASTIC_PASSWORD" ]; then
    echo "[-] 错误：.env 中未找到 ELASTIC_PASSWORD"
    exit 1
fi

# 增加重试机制，等待安全索引同步完成
MAX_RETRIES=10
RETRY_COUNT=0
LOGSTASH_API_KEY=""

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    RESPONSE=$(curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
        -X POST "https://localhost:9200/_security/api_key" \
        -H "Content-Type: application/json" \
        -d '{
          "name": "logstash-soc",
          "role_descriptors": {
            "logstash_writer": {
              "cluster": ["monitor", "read_ilm", "manage_index_templates", "manage_ingest_pipelines"],
              "index": [
                {
                  "names": ["*"],
                  "privileges": ["write", "create", "create_index", "auto_configure", "view_index_metadata"]
                }
              ]
            }
          }
        }')

    # 尝试解析 API Key
    LOGSTASH_API_KEY=$(echo "$RESPONSE" | jq -r 'if .id and .api_key then (.id + ":" + .api_key) else empty end' 2>/dev/null)

    if [ -n "$LOGSTASH_API_KEY" ] && [ "$LOGSTASH_API_KEY" != "null:null" ]; then
        break
    fi

    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "[!] API Key 生成失败 (尝试 $RETRY_COUNT/$MAX_RETRIES)，ES 响应: $RESPONSE"
    echo "[*] 等待 3 秒后重试..."
    sleep 3
done

if [ -z "$LOGSTASH_API_KEY" ] || [ "$LOGSTASH_API_KEY" = "null:null" ]; then
    echo "[-] 错误：API Key 生成失败，已达最大重试次数"
    echo "[-] 最后一次 ES 响应: $RESPONSE"
    exit 1
fi

echo "[+] logstash API Key 已生成并验证通过"

export LOGSTASH_API_KEY

# 写入 .env（追加）
grep -v '^LOGSTASH_API_KEY=' "$ENV_FILE" 2>/dev/null > "${ENV_FILE}.tmp" || true
echo "LOGSTASH_API_KEY=${LOGSTASH_API_KEY}" >> "${ENV_FILE}.tmp"
mv "${ENV_FILE}.tmp" "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "[+] logstash API Key 已生成并写入 .env"

# 4. 一键拉起整套 SOC 堆栈（Kibana, Suricata, Zeek）
echo "[*] 4. 正在拉起探针与展示层..."
docker compose up -d

echo "[*] 4.1 强制重启 logstash 以加载最新 API Key..."
docker compose up -d --force-recreate logstash

# 修改 Suricata 配置：community-id、payload、http-body-inline、local.rules
# jasonish/suricata 容器启动时会自动复制默认配置到挂载目录
SURICATA_YAML="/data/suricata/etc/suricata.yaml"
if [ -f "$SURICATA_YAML" ]; then
    # 创建 local.rules 文件（AI 自动生成的本地规则）
    # 规则目录与 suricata.yaml 的 default-rule-path 一致: /var/lib/suricata/rules
    touch /data/suricata/lib/rules/local.rules
    chmod 666 /data/suricata/lib/rules/local.rules

    sed -i -E \
      -e 's/community-id: false/community-id: true/' \
      -e '/- alert:/,/- frame:/ { s/# *(payload-buffer-size:)/\1/; s/# *(payload-printable:)/\1/ }' \
      -e 's/http-body-inline: auto/http-body-inline: yes/' \
      "$SURICATA_YAML"

    # 添加 local.rules 到 rule-files（相对于 default-rule-path，只需写文件名）
    # suricata 8.x unix-command 默认 enabled: auto，无需额外配置
    if ! grep -q 'local.rules' "$SURICATA_YAML"; then
        sed -i '/- suricata\.rules/a\  - local.rules' "$SURICATA_YAML"
    fi

    docker restart suricata
    echo "[+] Suricata 配置已更新并重启（含 local.rules 加载，suricatasc 热加载就绪）"
else
    echo "[-] 警告：Suricata 配置文件 $SURICATA_YAML 未找到，跳过配置修改。"
fi

echo "[*] 5. 更新 Suricata 规则 suricata-update (-f)，将显示实时输出："

docker exec --user suricata suricata suricata-update update-sources || true

echo "[*] 正在启用免费 Suricata 规则源（排除低价值源）..."
# 排除以下低价值噪音源：
#   oisf/trafficid           - 流量识别，产生大量低价值告警
#   pawpatrules              - emoji系列规则，告警噪音大
#   julioliraup/antiphishing - 钓鱼检测，质量未知且重复
#   ipfire/dbl               - 域名黑名单，娱乐/合规分类
ENABLED_MSG=$(docker exec suricata sh -c "suricata-update list-sources 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | tr -d '\r' | awk '/^Name:/{name=\$2} /^[[:space:]]+License:/{if(\$2!=\"Commercial\" && name!=\"oisf/trafficid\" && name!=\"pawpatrules\" && name!=\"julioliraup/antiphishing\" && name!=\"ipfire/dbl\") print name}' | tee /tmp/free_sources.txt | xargs -r -n1 suricata-update enable-source >/dev/null 2>&1; count=\$(wc -l < /tmp/free_sources.txt); rm -f /tmp/free_sources.txt; echo \"已启用 \${count} 个免费规则源\"")
echo "$ENABLED_MSG"

TMP_LOG=$(mktemp)
set +e
docker exec --user suricata suricata suricata-update -f 2>&1 | tee "$TMP_LOG"

RET=${PIPESTATUS[0]}
set -e

if [ "$RET" -eq 0 ]; then
    echo "[+] Suricata 规则已下载并重新加载。"
    rm -f "$TMP_LOG"
else
    echo "[-] suricata-update 返回退出码: $RET" >&2
    echo "[-] suricata-update 错误摘要：" >&2
    grep -v "<Info>" "$TMP_LOG" | tail -n 30 >&2
    rm -f "$TMP_LOG"
    
    echo "[-] Suricata 引擎日志（最后 200 行）：" >&2
    docker exec suricata sh -c 'tail -n 200 /var/log/suricata/suricata.log 2>/dev/null || true' >&2
    echo "[-] 注意：部分 Suricata 规则更新失败请使用 "docker exec --user suricata suricata suricata-update -f" 手动更新规则，脚本将继续执行后续步骤。" >&2
fi

# 6. 等待 Kibana 就绪并自动创建数据视图（Data View）
echo "[*] 6. 正在等待 Kibana 就绪并创建数据视图..."

KIBANA_READY=false
for i in $(seq 1 30); do
    KIBANA_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        -u "elastic:${ELASTIC_PASSWORD}" \
        "http://localhost:5601/api/status" 2>/dev/null) || true
    if [ "$KIBANA_CODE" = "200" ]; then
        KIBANA_READY=true
        echo "[+] Kibana 已就绪 (尝试 $i/30)"
        break
    fi
    printf "."
    sleep 3
done

if [ "$KIBANA_READY" != "true" ]; then
    echo ""
    echo "[-] 警告：Kibana 在 90 秒内未就绪，跳过数据视图创建。"
    echo "[-] 可稍后手动在 Kibana → Stack Management → Data Views 中创建 soc-*。"
else
    # 检查是否已存在 soc-* 数据视图（幂等）
    DV_SEARCH=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
        "http://localhost:5601/api/saved_objects/_find?type=index-pattern&search_fields=title&search=soc-%2A" 2>/dev/null)
    DV_COUNT=$(echo "$DV_SEARCH" | jq -r '.total // 0' 2>/dev/null)

    if [ "${DV_COUNT:-0}" != "0" ]; then
        echo "[+] Kibana 数据视图 soc-* 已存在，跳过创建。"
    else
        # 创建 soc-* 数据视图
        DV_RESPONSE=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
            -X POST "http://localhost:5601/api/saved_objects/index-pattern" \
            -H "Content-Type: application/json" \
            -H "kbn-xsrf: true" \
            -d '{"attributes":{"title":"soc-*","timeFieldName":"@timestamp"}}' 2>/dev/null)

        DV_ID=$(echo "$DV_RESPONSE" | jq -r '.id // empty' 2>/dev/null)

        if [ -n "$DV_ID" ]; then
            echo "[+] Kibana 数据视图 soc-* 已创建 (id: $DV_ID)"

            # 查找 config 对象 ID 并设为默认数据视图
            CONFIG_ID=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
                "http://localhost:5601/api/saved_objects/_find?type=config" 2>/dev/null \
                | jq -r '.saved_objects[0].id // empty' 2>/dev/null)

            if [ -n "$CONFIG_ID" ]; then
                curl -s -u "elastic:${ELASTIC_PASSWORD}" \
                    -X PUT "http://localhost:5601/api/saved_objects/config/${CONFIG_ID}" \
                    -H "Content-Type: application/json" \
                    -H "kbn-xsrf: true" \
                    -d "{\"attributes\":{\"defaultIndex\":\"${DV_ID}\"}}" >/dev/null 2>&1 || true
                echo "[+] 已将 soc-* 设为默认数据视图。"
            fi
        else
            echo "[-] 警告：Kibana 数据视图创建失败，响应: $DV_RESPONSE"
            echo "[-] 可稍后手动在 Kibana → Stack Management → Data Views 中创建 soc-*。"
        fi
    fi

    # soc-ai-* 数据视图由 ndjson 仪表板导入时自带，无需单独创建

    # 导入 SenseMind AI 研判仪表板（含 soc-ai-* 数据视图）
    DASHBOARD_FILE="$BASE_DIR/kibana/sensemind-ai-dashboard.ndjson"
    if [ -f "$DASHBOARD_FILE" ]; then
        echo "[*] 导入 SenseMind AI 研判仪表板..."
        IMPORT_RESP=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
            -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" \
            -H "kbn-xsrf: true" \
            -F "file=@${DASHBOARD_FILE}" 2>/dev/null)
        IMPORT_SUCCESS=$(echo "$IMPORT_RESP" | jq -r '.success // empty' 2>/dev/null)
        if [ "$IMPORT_SUCCESS" = "true" ]; then
            echo "[+] SenseMind AI 研判仪表板已导入"
            echo "    访问地址: http://<服务器IP>:5601/app/dashboards#/view/sensemind-ai-dashboard"
        else
            echo "[-] 警告：仪表板导入失败: $IMPORT_RESP"
        fi
    fi

    # 兜底检查：仪表板导入后确认 soc-ai-* 数据视图存在（导入失败时补建）
    AI_DV_SEARCH=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" \
        "http://localhost:5601/api/saved_objects/_find?type=index-pattern&search_fields=title&search=soc-ai-%2A" 2>/dev/null)
    AI_DV_COUNT=$(echo "$AI_DV_SEARCH" | jq -r '.total // 0' 2>/dev/null)
    if [ "${AI_DV_COUNT:-0}" = "0" ]; then
        echo "[*] soc-ai-* 数据视图不存在，补建..."
        curl -s -u "elastic:${ELASTIC_PASSWORD}" \
            -X POST "http://localhost:5601/api/saved_objects/index-pattern" \
            -H "Content-Type: application/json" \
            -H "kbn-xsrf: true" \
            -d '{"attributes":{"title":"soc-ai-*","timeFieldName":"@timestamp"}}' >/dev/null 2>&1
        echo "[+] soc-ai-* 数据视图已补建"
    else
        echo "[+] Kibana 数据视图 soc-ai-* 已存在"
    fi
fi

# 7. 阅后即焚：擦除 Shell 进程中的环境变量
unset KIBANA_KEY_1 KIBANA_KEY_2 KIBANA_KEY_3 KIBANA_TOKEN PUID PGID
echo "[+] =============================================="
echo "[+] SOC 堆栈已安全启动。当前 Shell 敏感凭据已全数清空！"
