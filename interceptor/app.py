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
import json
import ssl
from pathlib import Path
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as redis
from interceptor.metrics import MetricsCollector

from interceptor.config import load_policy
from interceptor.auth import JwtVerifier
from interceptor.taint import TaintEngine
from interceptor.durable_state import DurableState, DurableTaintEngine, SingleWorkerLock
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
    root_key = _macaroon_root()
    if cfg.env == "prod":
        if cfg.taint_mode != "coarse" or cfg.enforcement_mode != "enforce":
            raise RuntimeError("Production beta requires coarse taint and enforce mode")
        if not cfg.schema_lock_enforce or cfg.schema_lock_learn or not cfg.dlp_egress_enabled:
            raise RuntimeError("Production beta requires schema enforcement, no learning, and DLP enabled")
        if not cfg.upstream_url.startswith("https://"):
            raise RuntimeError("Production upstream must use HTTPS")
    data_dir = Path(os.environ.get("EVILGUM_DATA_DIR", "data")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    if (data_dir / "initialized.json").exists() and any(not (data_dir / name).exists() for name in ("admin.db", "security.db", "audit.log.jsonl")):
        raise RuntimeError("Incomplete durable state; restore a verified backup")
    expected_db = "sqlite+aiosqlite:///" + str(data_dir / "admin.db").replace("\\", "/")
    if os.environ.get("DATABASE_URL", expected_db) != expected_db:
        raise RuntimeError("Production beta DATABASE_URL must point to admin.db in EVILGUM_DATA_DIR")
    cfg.audit_required = True
    cfg.legacy_rpc_enabled = cfg.env != "prod"
    worker_lock = SingleWorkerLock(data_dir)
    state = DurableState(data_dir / "security.db")

    if cfg.upstream_tls_verify:
        verify = ssl.create_default_context(cafile=cfg.upstream_ca_bundle)
    else:
        # Only reachable if an operator explicitly disabled verification in non-prod.
        if cfg.env == "prod":
            raise RuntimeError("Refusing to start: UPSTREAM_TLS_VERIFY=false is not allowed in prod.")
        verify = False

    if bool(cfg.client_cert) != bool(cfg.client_key):
        raise RuntimeError("CLIENT_CERT and CLIENT_KEY must be supplied together")
    if cfg.client_cert:
        if verify is False:
            raise RuntimeError("Client certificates require verified TLS")
        verify.load_cert_chain(cfg.client_cert, cfg.client_key)
    http_client = httpx.AsyncClient(
        verify=verify,
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        timeout=httpx.Timeout(30.0),
    )

    r_taint = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
    r_rate = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)

    rbac = RbacEngine(sqlalchemy_role_loader, cache_ttl=0.0)
    webhook_url = os.environ.get("WEBHOOK_URL")
    _alert_client = httpx.AsyncClient(verify=True, timeout=httpx.Timeout(5.0))

    async def alert_hook(kind: str, details: str) -> None:
        if not webhook_url:
            return
        try:
            await _alert_client.post(webhook_url, json={"type": kind, "details": details})
        except Exception as e:
            logger.error("alert dispatch failed: %s", e)

    deps = Deps(
        verifier=JwtVerifier(cfg),
        taint=DurableTaintEngine(cfg, state, redis_client=r_taint),
        rbac=rbac,
        rate_limiter=RedisTokenBucketRateLimiter(100, 50.0, redis_client=r_rate),
        waf=SemanticWaf(analyzer=PresidioAnalyzer(), max_bytes=cfg.dlp_max_bytes,
                        dlp_enabled=cfg.dlp_egress_enabled, fail_closed=True),
        schema_lock=SchemaLock.load(os.environ.get("SCHEMA_LOCK_PATH", "mcp-lock.json"), enforce=cfg.schema_lock_enforce, learn=cfg.schema_lock_learn),
        egress=EgressGuard(),
        http_client=http_client,
        macaroon=MacaroonEvaluator(root_key),
        alert_hook=alert_hook,
        admin_router=admin_router,
        audit=AuditLog(os.environ.get("AUDIT_LOG_PATH", str(data_dir / "audit.log.jsonl"))),
        metrics=MetricsCollector(),
    )
    deps.schema_lock.bind_state(state)
    if (data_dir / "recovery.json").exists():
        deps.verifier.required_recovery_epoch = json.loads((data_dir / "recovery.json").read_text())["epoch"]

    async def readiness():
        state.quarantined()
        from interceptor.admin import engine
        from sqlalchemy import text
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1 FROM tenant_roles LIMIT 1"))
    deps.readiness_check = readiness

    @asynccontextmanager
    async def lifespan(app):
        worker_lock.acquire()
        try:
            epoch_file = data_dir / "recovery.json"
            if not epoch_file.exists():
                raise RuntimeError("Initialize a fresh data volume using python -m interceptor.recovery init; do not reuse old session tokens")
            deps.verifier.required_recovery_epoch = json.loads(epoch_file.read_text())["epoch"]
            if not deps.verifier.required_recovery_epoch:
                raise RuntimeError("Invalid deployment epoch")
            if (data_dir / "initialized.json").exists() and any(not (data_dir / name).exists() for name in ("admin.db", "security.db", "audit.log.jsonl")):
                raise RuntimeError("Incomplete durable state; restore a verified backup")
            deps.audit = AuditLog(deps.audit.path)
            deps.schema_lock.bind_state(state)
            await init_db()
            deps.waf.analyzer.find("Startup health check")
            await r_rate.ping()
            deps.audit.append({"outcome": "startup", "policy": "durable-coarse"})
            (data_dir / "initialized.json").write_text('{"initialized":true}')
            yield
        finally:
            await http_client.aclose()
            await _alert_client.aclose()
            await deps.taint.close()
            await deps.rate_limiter.close()
            worker_lock.close()

    app = create_app(cfg, deps, lifespan=lifespan)
    # /metrics (Prometheus), /healthz and /readyz are registered by create_app.
    # NOTE: scrape /metrics from inside the mesh; don't expose it publicly.
    return app


# Build eagerly for `uvicorn interceptor.app:app` (fail fast on bad config).
# Tests set GATEWAY_SKIP_AUTOBUILD=1 and call build_production_app() directly.
app = None
if os.environ.get("GATEWAY_SKIP_AUTOBUILD") != "1":
    app = build_production_app()
