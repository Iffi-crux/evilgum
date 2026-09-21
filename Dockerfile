FROM python:3.11-slim@sha256:da047cb8f9d1d98e5c070f5300ba9f7274e33b8fc0e5be5ed88740aed1b95ba9
WORKDIR /app
COPY locks/runtime-py311-linux.lock /tmp/runtime.lock
RUN --mount=type=cache,id=evilgum-release-pip,target=/root/.cache/pip pip install --require-hashes -r /tmp/runtime.lock
COPY dist/evilgum-0.1.0rc1-py3-none-any.whl /tmp/evilgum.whl
RUN mv /tmp/evilgum.whl /tmp/evilgum-0.1.0rc1-py3-none-any.whl && pip install --no-deps /tmp/evilgum-0.1.0rc1-py3-none-any.whl && pip check && evilgum init-config --directory /app
RUN useradd -m -u 10001 gateway && mkdir -p /app/data && chown -R gateway /app
USER gateway
ENV EVILGUM_DATA_DIR=/app/data DATABASE_URL=sqlite+aiosqlite:////app/data/admin.db
LABEL org.opencontainers.image.source="https://github.com/Iffi-crux/evilgum" org.opencontainers.image.version="0.1.0rc1" org.opencontainers.image.licenses="Apache-2.0"
EXPOSE 8080
CMD ["uvicorn", "interceptor.app:app", "--host", "0.0.0.0", "--port", "8080"]
