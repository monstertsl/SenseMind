FROM python:3.12-slim

LABEL maintainer="SenseMind"
LABEL description="AI Security Analysis Center - LangChain + OpenAI-compatible LLM"

WORKDIR /usr/share/ai-analyzer

# 切换 apt 为阿里云镜像源（国内构建加速）
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources

# 安装系统依赖
# curl: 健康检查
# docker.io: 提供 docker CLI，用于 docker exec suricata suricatasc 热加载规则
# logrotate: 原始日志按天轮转（copytruncate 模式，配合 scheduler.py 清理过期归档）
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl docker.io logrotate && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/lib/logrotate && \
    touch /var/lib/logrotate/status

# 先复制依赖文件，利用 Docker 缓存层
COPY requirements.txt .
# 使用清华镜像源 + BuildKit 缓存加速 pip 安装
# 语法 --mount=type=cache 需要 BuildKit（Docker 23+ 默认开启，或设 DOCKER_BUILDKIT=1）
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

# 复制应用代码
COPY app/ ./app/
COPY config.yaml .
COPY knowledge/ ./knowledge/
COPY logrotate-sensemind-raw-logs /etc/logrotate.d/sensemind-raw-logs
RUN chmod 644 /etc/logrotate.d/sensemind-raw-logs

# 暴露 webhook 端口
EXPOSE 9090

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

# 启动
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9090"]
