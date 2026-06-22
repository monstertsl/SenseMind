FROM python:3.12-slim

LABEL maintainer="SenseMind"
LABEL description="AI Security Analysis Center - LangChain + OpenAI-compatible LLM"

WORKDIR /usr/share/ai-analyzer

# 安装系统依赖
# curl: 健康检查
# docker.io: 提供 docker CLI，用于 docker exec suricata suricatasc 热加载规则
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl docker.io && \
    rm -rf /var/lib/apt/lists/*

# 先复制依赖文件，利用 Docker 缓存层
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY app/ ./app/
COPY config.yaml .
COPY knowledge/ ./knowledge/

# 暴露 webhook 端口
EXPOSE 9090

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

# 启动
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9090"]
