"""
Production entrypoint. Builds the hardened gateway from real dependencies and
the single policy source. Run: uvicorn interceptor.app:app --host 0.0.0.0 --port 8080

Required environment (the gateway REFUSES TO START without safe values):
  GATEWAY_JWT_ALG=RS256|ES256           (HS256 allowed only when GATEWAY_ENV=dev)
  GATEWAY_JWT_PUBLIC_KEY=<PEM>          (asymmetric) or GATEWAY_JWT_SECRET (dev HS*)
  GATEWAY_JWT_AUDIENCE / GATEWAY_JWT_ISSUER
  MACAROON_ROOT_KEY=<>=32 bytes>       (no known placeholder)
  UPSTREAM_MCP_URL, UPSTREAM_CA_BUNDLE, CLIENT_CERT, CLIENT_KEY (for mTLS)
  REDIS_URL, DATABASE_URL, WEBHOOK_URL
"""
from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as redis
from interceptor.metrics import MetricsCollector

from interceptor.config import load_policy
from interceptor.auth import JwtVerifier
from interceptor.taint import TaintEngine
from interceptor.rbac import RbacEngine
from interceptor.rate_limiter import RedisTokenBucketRateLimiter
from interceptor.schema_lock import SchemaLock
from interceptor.egress_guard import EgressGuard
from interceptor.admin import router as admin_router, init_db, sqlalchemy_role_loader
from interceptor.audit import AuditLog
from mesh.semantic_waf import SemanticWaf, PresidioAnalyzer
from mesh.sidecar import MacaroonEvaluator
from interceptor.proxy import create_app, Deps

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gateway")

_BANNED_ROOT_KEYS = {b"anti_gravity_root_key", b"root_secret", b"", b"changeme"}


def _macaroon_root() -> bytes:
    raw = os.environ.get("MACAROON_ROOT_KEY", "").encode()
    if raw in _BANNED_ROOT_KEYS or len(raw) < 32:
        raise RuntimeError("Refusing to start: MACAROON_ROOT_KEY missing/placeholder/<32 bytes.")
    return raw


def build_production_app():
    cfg = load_policy(os.environ.get("CONFIG_PATH", "config.yaml"))

    if cfg.upstream_tls_verify:
        verify = cfg.upstream_ca_bundle or True   # CA bundle path pins the upstream; True uses system CAs
    else:
        # Only reachable if an operator explicitly disabled verification in non-prod.
        if cfg.env == "prod":
            raise RuntimeError("Refusing to start: UPSTREAM_TLS_VERIFY=false is not allowed in prod.")
        verify = False

    cert = (cfg.client_cert, cfg.client_key) if cfg.client_cert and cfg.client_key else None
    http_client = httpx.AsyncClient(
        cert=cert, verify=verify,
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        timeout=httpx.Timeout(30.0),
    )

    r_taint = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
    r_rate = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)

    rbac = RbacEngine(sqlalchemy_role_loader, cache_ttl=float(os.environ.get("RBAC_CACHE_TTL", "30")))
    webhook_url = os.environ.get("WEBHOOK_URL")
    _alert_client = httpx.AsyncClient(verify=verify, timeout=httpx.Timeout(5.0))

    async def alert_hook(kind: str, details: str) -> None:
        if not webhook_url:
            return
        try:
            await _alert_client.post(webhook_url, json={"type": kind, "details": details})
        except Exception as e:
            logger.error("alert dispatch failed: %s", e)

    deps = Deps(
        verifier=JwtVerifier(cfg),
        taint=TaintEngine(cfg, redis_client=r_taint),
        rbac=rbac,
        rate_limiter=RedisTokenBucketRateLimiter(100, 50.0, redis_client=r_rate),
        waf=SemanticWaf(analyzer=PresidioAnalyzer(), max_bytes=cfg.dlp_max_bytes,
                        dlp_enabled=cfg.dlp_egress_enabled),
        schema_lock=SchemaLock.load("mcp-lock.json", enforce=cfg.schema_lock_enforce, learn=cfg.schema_lock_learn),
        egress=EgressGuard(),
        http_client=http_client,
        macaroon=MacaroonEvaluator(_macaroon_root()),
        alert_hook=alert_hook,
        admin_router=admin_router,
        audit=AuditLog(os.environ.get("AUDIT_LOG_PATH", "data/audit.log.jsonl")),
        metrics=MetricsCollector(),
    )

    @asynccontextmanager
    async def lifespan(app):
        await init_db()
        yield
        await http_client.aclose()
        await _alert_client.aclose()
        await deps.taint.close()
        await deps.rate_limiter.close()

    app = create_app(cfg, deps, lifespan=lifespan)
    # /metrics (Prometheus), /healthz and /readyz are registered by create_app.
    # NOTE: scrape /metrics from inside the mesh; don't expose it publicly.
    return app


# Build eagerly for `uvicorn interceptor.app:app` (fail fast on bad config).
# Tests set GATEWAY_SKIP_AUTOBUILD=1 and call build_production_app() directly.
app = None
if os.environ.get("GATEWAY_SKIP_AUTOBUILD") != "1":
    app = build_production_app()
