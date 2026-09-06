FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m spacy download en_core_web_lg

COPY interceptor/ ./interceptor/
COPY detector/ ./detector/
COPY mesh/ ./mesh/
COPY config.yaml mcp-lock.json ./

# Run as non-root
RUN useradd -m gateway && chown -R gateway /app
USER gateway

EXPOSE 8080

# V6: factory-built app from real deps (was interceptor.proxy:app in V5).
CMD ["uvicorn", "interceptor.app:app", "--host", "0.0.0.0", "--port", "8080"]
