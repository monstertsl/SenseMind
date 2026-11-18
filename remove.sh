#!/usr/bin/env bash
# SenseMind SOC 平台清理脚本
# 彻底清理容器、网络、数据卷及本地数据目录
#
# 用法:
#   ./remove.sh          清理中心节点（默认）
#   ./remove.sh probe    清理探针节点（需在探针机仓库目录执行）

set -euo pipefail

MODE="${1:-center}"
case "$MODE" in
    center) COMPOSE_FILE="docker-compose.yml" ;;
    probe)  COMPOSE_FILE="docker-compose-probe.yml" ;;
    *) echo "[-] 错误：未知模式 '$MODE'（可选: center / probe）"; exit 1 ;;
esac

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "[-] 错误：当前目录未找到 $COMPOSE_FILE（请在仓库根目录执行）"
    exit 1
fi

# 0. 确认操作
echo "========================================="
echo "  SenseMind SOC 平台清理脚本（模式: ${MODE}）"
if [ "$MODE" = "center" ]; then
    echo "  将删除所有容器、数据卷、本地数据目录"
    echo "  包括: Elasticsearch / Suricata / Zeek / PostgreSQL / ai-analyzer / web"
    echo "  以及: /data/suricata, /data/zeek, .env, certs/"
else
    echo "  将删除探针容器、数据卷及本地数据目录"
    echo "  包括: probe-suricata / probe-zeek / probe-filebeat / probe-agent"
    echo "  以及: /data/suricata, /data/zeek, /data/probe-agent, certs/, .env"
fi
echo "========================================="
read -p "确认清理? (输入 yes 继续): " CONFIRM
if [ "${CONFIRM}" != "yes" ]; then
    echo "已取消。"
    exit 0
fi
echo ""

# 1. 在 .env 尚存在时，先获取 compose 项目名前缀（用于清理残留命名卷）
#    docker compose 的项目名默认取自目录名（小写），命名卷格式为: <项目名>_<卷名>
COMPOSE_PREFIX="$(docker compose -f "$COMPOSE_FILE" config --format json 2>/dev/null \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("name",""))' 2>/dev/null || true)"
if [ -z "${COMPOSE_PREFIX}" ]; then
    COMPOSE_PREFIX="$(basename "$PWD" | tr '[:upper:]' '[:lower:]')"
fi

echo "==> Compose 项目前缀: ${COMPOSE_PREFIX}"

# 2. 停止并删除容器、compose 文件中声明的命名卷及孤立容器
#    中心声明卷: esdata, filebeat-data, pgdata；探针声明卷: filebeat-probe-data
echo "==> 停止并删除 compose 服务及声明的数据卷..."
docker compose -f "$COMPOSE_FILE" down -v --remove-orphans

# 3. 清理 compose 未声明但属于本项目的残留命名卷（如历史遗留的 es_certs）
#    docker compose down -v 只删除当前 compose 文件声明的卷，
#    历史残留的命名卷需按项目前缀显式删除。
echo "==> 清理项目前缀下的残留命名卷..."
docker volume ls -q --filter "name=^${COMPOSE_PREFIX}_" | xargs -r docker volume rm

# 4. 清理悬空容器/网络/匿名卷
echo "==> 清理悬空容器..."
docker container prune -f
echo "==> 清理悬空网络..."
docker network prune -f
echo "==> 清理悬空匿名卷..."
docker volume prune -f

# 5. 删除本地数据目录与配置文件
echo "==> 删除本地数据目录与配置文件..."
if [ "$MODE" = "center" ]; then
    # /data/suricata: Suricata 日志和规则
    # /data/zeek: Zeek 日志
    # .env: 环境变量（含密码和密钥）
    # ./certs: ES/探针 CA 证书
    sudo rm -rf /data/suricata /data/zeek .env .env.bak ./certs
else
    sudo rm -rf /data/suricata /data/zeek /data/probe-agent .env .env.bak ./certs
    # 探针的 /etc/systemd timesyncd 配置由 agent 恢复原样，无残留
fi

# 6. 确认 PostgreSQL 数据卷已清理（仅中心模式）
if [ "$MODE" = "center" ]; then
    PG_VOLUME="${COMPOSE_PREFIX}_pgdata"
    if docker volume inspect "$PG_VOLUME" >/dev/null 2>&1; then
        echo "==> 清理残留 PostgreSQL 数据卷: $PG_VOLUME"
        docker volume rm "$PG_VOLUME" || true
    fi
fi

echo "==> 清理完成。"
if [ "$MODE" = "center" ]; then
    echo ""
    echo "注意: .env 中的 SECRET_KEY 和 ENCRYPT_KEY 如果已用于签名 JWT 或加密 TOTP 密钥，"
    echo "      重新部署后会生成新密钥，之前签发的 token 和 TOTP 配置将失效。"
else
    echo ""
    echo "注意: 中心设备管理中该设备的注册记录仍在（active 状态）。"
    echo "      重装同一设备请使用「重装覆盖签发」生成新凭证；全新设备直接「添加设备」。"
fi
