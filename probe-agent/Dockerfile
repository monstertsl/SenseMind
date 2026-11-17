# SenseMind 探针 agent 容器（合并原 probe-agent.sh timer + probe-logrotate 工具容器）
# Python 长驻：健康采集（与中心同源同口径）/ 心跳批量上报 / 配置下发 / 吊销停服 / 原始日志轮转
FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends logrotate curl tzdata && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir httpx psutil

# 共享采集模块（同步义务见文件头注释）+ agent 主程序 + logrotate 模板（提取自中心）
COPY metrics_common.py /app/metrics_common.py
COPY agent.py /app/agent.py
COPY logrotate.tmpl /etc/logrotate.d/logrotate-probe.conf.tmpl

WORKDIR /app
ENV TZ=Asia/Shanghai
CMD ["python", "-u", "agent.py"]
