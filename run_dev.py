"""Dev launcher: the REAL gateway pipeline, with an in-memory Redis + a stub upstream
so it runs with zero external services. uvicorn run_dev:app"""
from interceptor.config import PolicyConfig
from interceptor.auth import JwtVerifier
from interceptor.taint import TaintEngine
from interceptor.rbac import RbacEngine
from interceptor.rate_limiter import RedisTokenBucketRateLimiter
from interceptor.schema_lock import SchemaLock
from interceptor.egress_guard import EgressGuard
from mesh.semantic_waf import SemanticWaf
from mesh.sidecar import MacaroonEvaluator
from interceptor.proxy import create_app, Deps
import fakeredis.aioredis as fr

cfg = PolicyConfig()
cfg.env = "dev"; cfg.jwt_alg = "HS256"
cfg.jwt_secret = "dev-only-change-me-3f9c1a7b2e5d4680"
cfg.upstream_url = "http://stub/rpc"
cfg.schema_lock_enforce = False


class Resp:
    def __init__(self, p): self.p = p
    def raise_for_status(self): pass
    def json(self): return self.p


class StubUpstream:
    async def post(self, url, json=None):
        name = (json.get("params") or {}).get("name")
        return Resp({"jsonrpc": "2.0", "id": json.get("id"),
                     "result": {"status": "success", "output": f"Tool {name} executed."}})


roles = {"agent-1": ["read_file", "fetch_url"]}   # NOTE: execute_bash NOT granted


async def loader(agent_id):
    return roles.get(agent_id)


deps = Deps(
    verifier=JwtVerifier(cfg),
    taint=TaintEngine(cfg, redis_client=fr.FakeRedis(decode_responses=True)),
    rbac=RbacEngine(loader, cache_ttl=0.0),
    rate_limiter=RedisTokenBucketRateLimiter(1000, 500.0, redis_client=fr.FakeRedis(decode_responses=True)),
    waf=SemanticWaf(analyzer=None, dlp_enabled=False),
    schema_lock=SchemaLock({}, enforce=False),
    egress=EgressGuard(),
    http_client=StubUpstream(),
    macaroon=MacaroonEvaluator(b"dev-macaroon-root-key-0123456789abcdef"),
)
app = create_app(cfg, deps)
