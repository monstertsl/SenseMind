FROM python:3.12-slim

LABEL maintainer="SenseMind"
LABEL description="SenseMind alert delivery and response service"

WORKDIR /usr/share/alert-responder

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

COPY app/ ./app/

EXPOSE 9091

HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9091/health', timeout=3)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9091"]