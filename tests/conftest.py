import time
import json
import dataclasses
import pytest
import jwt
from fastapi import APIRouter
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import fakeredis.aioredis as fakeredis

from interceptor.config import PolicyConfig
from interceptor.auth import JwtVerifier
from interceptor.taint import TaintEngine
from interceptor.rbac import RbacEngine
from interceptor.rate_limiter import RedisTokenBucketRateLimiter
from interceptor.schema_lock import SchemaLock
from interceptor.egress_guard import EgressGuard
from mesh.semantic_waf import SemanticWaf, PiiSpan
from mesh.sidecar import MacaroonEvaluator
from interceptor.proxy import create_app, Deps

ISS = "test-idp"
AUD = "mcp-gateway"


@pytest.fixture(scope="session")
def rsa_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


@pytest.fixture
def cfg(rsa_keys):
    _, pub = rsa_keys
    c = PolicyConfig()
    c.env = "prod"
    c.jwt_alg = "RS256"
    c.jwt_public_key = pub
    c.jwt_audience = AUD
    c.jwt_issuer = ISS
    c.upstream_url = "https://upstream.local/rpc"
    return c


def make_token(priv, sub="agent-1", scopes="", sid="sess-1", exp_delta=300,
               aud=AUD, iss=ISS, alg="RS256", key=None, omit=None, tenant=None):
    now = int(time.time())
    claims = {"sub": sub, "scope": scopes, "sid": sid, "iat": now,
              "exp": now + exp_delta, "aud": aud, "iss": iss, "jti": "jti-" + sid}
    if tenant is not None:
        claims["tenant"] = tenant
    for k in (omit or []):
        claims.pop(k, None)
    return jwt.encode(claims, key or priv, algorithm=alg)


class FakeResp:
    def __init__(self, payload):
        self._p = payload
    def raise_for_status(self): pass
    def json(self): return self._p


class FakeUpstream:
    """Records what the gateway forwarded and returns a scripted response."""
    def __init__(self, response):
        self.response = response
        self.last_sent = None
        self.called = False
    async def post(self, url, json=None):
        self.called = True
        self.last_sent = json
        r = self.response(json) if callable(self.response) else self.response
        return FakeResp(r)


class StubPii:
    """Deterministic PII finder for tests (no spaCy/Presidio needed)."""
    def find(self, text):
        spans = []
        idx = text.find("4111111111111111")
        if idx >= 0:
            spans.append(PiiSpan("CREDIT_CARD", idx, idx + 16))
        return spans


@pytest.fixture
def build(cfg, rsa_keys):
    priv, _ = rsa_keys

    def _build(*, roles=None, upstream=None, macaroon_root=b"a-strong-root-key-32bytes-xxxxxx",
               schema_locks=None, enforce_lock=True, learn=False, pii=None, cfg_overrides=None,
               rate_capacity=1000, rate_refill=500.0, alert_hook=None,
               rate_limiter=None, rbac=None, taint=None, audit=None, metrics=None):
        c = dataclasses.replace(cfg, **(cfg_overrides or {}))
        r = fakeredis.FakeRedis(decode_responses=True)
        r2 = fakeredis.FakeRedis(decode_responses=True)
        roles = roles or {}

        async def loader(agent_id):
            return roles.get(agent_id)

        up = upstream or FakeUpstream({"jsonrpc": "2.0", "id": 1, "result": {}})
        deps = Deps(
            verifier=JwtVerifier(c),
            taint=taint or TaintEngine(c, redis_client=r),
            rbac=rbac or RbacEngine(loader, cache_ttl=0.0),
            rate_limiter=rate_limiter or RedisTokenBucketRateLimiter(rate_capacity, rate_refill, redis_client=r2),
            waf=SemanticWaf(analyzer=pii, max_bytes=c.dlp_max_bytes, dlp_enabled=c.dlp_egress_enabled),
            schema_lock=SchemaLock(schema_locks or {}, enforce=enforce_lock, learn=learn),
            egress=EgressGuard(),
            http_client=up,
            macaroon=MacaroonEvaluator(macaroon_root),
            alert_hook=alert_hook,
            audit=audit,
            metrics=metrics,
        )
        # Minimal in-memory admin router to exercise the scope guard.
        admin = APIRouter(prefix="/admin", tags=["admin"])

        @admin.post("/roles/{agent_id}")
        async def _update_role(agent_id: str, allowed_tools: list[str]):
            roles[agent_id] = allowed_tools
            return {"status": "ok", "agent_id": agent_id, "allowed_tools": allowed_tools}

        deps.admin_router = admin
        app = create_app(c, deps)
        return app, deps, up, priv
    return _build
