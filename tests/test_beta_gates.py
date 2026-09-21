"""Release gates: exercise bypasses through the actual HTTP pipeline."""
import pytest
from fastapi.testclient import TestClient
from interceptor.schema_lock import compute_hash
from interceptor.rbac import RbacEngine
from tests.conftest import make_token, FakeUpstream

TOOL = {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}}
CALL = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {}}}

def post(client, priv, payload, **claims):
    return client.post("/rpc", json=payload, headers={"Authorization": "Bearer " + make_token(priv, **claims)})

def test_direct_unpinned_call_never_reaches_upstream(build):
    app, deps, upstream, priv = build(roles={"agent-1": ["read_file"]}, schema_locks={})
    with TestClient(app) as client:
        assert post(client, priv, CALL).json()["error"]["code"] == -32002
    assert not upstream.called

def test_pin_requires_observation_and_drift_stays_quarantined(build):
    upstream = FakeUpstream({"jsonrpc": "2.0", "id": 1, "result": {"tools": [TOOL]}})
    app, deps, upstream, priv = build(roles={"agent-1": ["read_file"]}, upstream=upstream,
                                    schema_locks={"read_file": compute_hash(TOOL)})
    with TestClient(app) as client:
        assert post(client, priv, CALL).json()["error"]["code"] == -32002
        assert not upstream.called
        listing = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        assert "result" in post(client, priv, listing).json()
        upstream.response = {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}
        assert "result" in post(client, priv, CALL).json()
        upstream.response = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{**TOOL, "description": "Changed"}]}}
        assert post(client, priv, listing).json()["error"]["code"] == -32002
        upstream.called = False
        assert post(client, priv, CALL).json()["error"]["code"] == -32002
        assert not upstream.called
        upstream.response = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [TOOL]}}
        assert post(client, priv, listing).json()["error"]["code"] == -32002

@pytest.mark.parametrize("method", ["resources/read", "resources/list", "prompts/get", "prompts/list", "completion/complete"])
@pytest.mark.parametrize("mode", ["enforce", "shadow", "off"])
def test_unsupported_surface_never_forwarded(build, method, mode):
    app, deps, upstream, priv = build(cfg_overrides={"enforcement_mode": mode, "method_allowlist_enforce": False})
    with TestClient(app) as client:
        assert post(client, priv, {"jsonrpc": "2.0", "id": 1, "method": method}).status_code == 400
    assert not upstream.called

@pytest.mark.asyncio
async def test_role_cache_and_revocation_are_tenant_scoped():
    store = {("acme", "same-agent"): ["read_file"], ("globex", "same-agent"): ["execute_bash"]}
    async def loader(tenant_id, agent_id):
        return store.get((tenant_id, agent_id))
    engine = RbacEngine(loader)
    assert await engine.is_authorized("same-agent", "read_file", tenant_id="acme")
    assert not await engine.is_authorized("same-agent", "read_file", tenant_id="globex")
    store[("acme", "same-agent")] = []
    engine.invalidate("same-agent", tenant_id="acme")
    assert not await engine.is_authorized("same-agent", "read_file", tenant_id="acme")
    assert await engine.is_authorized("same-agent", "execute_bash", tenant_id="globex")

def test_real_admin_routes_cannot_read_or_mutate_other_tenant(build, monkeypatch):
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from interceptor import admin
    from interceptor.proxy import create_app

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(admin, "AsyncSessionLocal", sessions)
    async def initialize():
        async with engine.begin() as conn:
            await conn.run_sync(admin.Base.metadata.create_all)
    asyncio.run(initialize())
    original, deps, upstream, priv = build()
    deps.admin_router = admin.router
    deps.rbac = RbacEngine(admin.sqlalchemy_role_loader)
    app = create_app(original.state.cfg, deps)
    def headers(tenant, scope="mcp.admin"):
        return {"Authorization": "Bearer " + make_token(priv, tenant=tenant, scopes=scope)}
    try:
        with TestClient(app) as client:
            path = "/admin/roles/same-agent"
            assert client.post(path, json=["read_file"], headers=headers("acme")).status_code == 200
            assert client.get(path, headers=headers("globex")).json() == {"allowed_tools": []}
            assert client.post(path, json=["execute_bash"], headers=headers("globex")).status_code == 200
            assert client.get(path, headers=headers("acme")).json() == {"allowed_tools": ["read_file"]}
            assert client.post(path, json=[], headers=headers("acme", "")).status_code == 403
            assert client.get(path, headers=headers("acme")).json() == {"allowed_tools": ["read_file"]}
            assert client.post(path, json=[], headers=headers("globex")).status_code == 200
            assert client.get(path, headers=headers("acme")).json() == {"allowed_tools": ["read_file"]}
    finally:
        asyncio.run(engine.dispose())

def test_non_listing_response_cannot_verify_a_pin(build):
    upstream = FakeUpstream({"jsonrpc": "2.0", "id": 1, "result": {"tools": [TOOL]}})
    app, deps, upstream, priv = build(roles={"agent-1": ["read_file"]}, upstream=upstream,
                                    schema_locks={"read_file": compute_hash(TOOL)})
    with TestClient(app) as client:
        post(client, priv, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        upstream.called = False
        assert post(client, priv, CALL).json()["error"]["code"] == -32002
        assert not upstream.called

def test_later_drift_is_quarantined_even_if_first_tool_is_unpinned(build):
    upstream = FakeUpstream({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {**TOOL, "name": "unknown"}, {**TOOL, "description": "Changed"}]}})
    app, deps, upstream, priv = build(roles={"agent-1": ["read_file"]}, upstream=upstream,
                                    schema_locks={"read_file": compute_hash(TOOL)})
    deps.schema_lock.check(TOOL)
    with TestClient(app) as client:
        post(client, priv, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        upstream.called = False
        assert post(client, priv, CALL).json()["error"]["code"] == -32002
        assert not upstream.called
