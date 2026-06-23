#!/usr/bin/env bash
# SOC (Elastic + Suricata + Zeek) 清理脚本
# 彻底清理容器、网络、数据卷及本地数据目录

set -euo pipefail

# 1. 在 .env 尚存在时，先获取 compose 项目名前缀（用于清理残留命名卷）
#    docker compose 的项目名默认取自目录名（小写），命名卷格式为: <项目名>_<卷名>
COMPOSE_PREFIX="$(docker compose config --format json 2>/dev/null \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("name",""))' 2>/dev/null || true)"
if [ -z "${COMPOSE_PREFIX}" ]; then
    COMPOSE_PREFIX="$(basename "$PWD" | tr '[:upper:]' '[:lower:]')"
fi

echo "==> Compose 项目前缀: ${COMPOSE_PREFIX}"

# 2. 停止并删除容器、compose 文件中声明的命名卷及孤立容器
echo "==> 停止并删除 compose 服务及声明的数据卷..."
docker compose down -v --remove-orphans

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
sudo rm -rf /data/suricata /data/zeek .env .env.bak ./certs

echo "==> 清理完成。"
