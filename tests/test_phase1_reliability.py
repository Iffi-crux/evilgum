import asyncio
import json
import sqlite3
import pytest
import fakeredis.aioredis
from starlette.testclient import TestClient
from interceptor.auth import Principal, JwtVerifier, AuthError
from interceptor.config import PolicyConfig
from interceptor.durable_state import DurableState, DurableTaintEngine, SingleWorkerLock
from interceptor.schema_lock import SchemaLock, compute_hash
from interceptor.audit import AuditLog
from interceptor.recovery import backup, restore, initialize
from interceptor.recovery import release_quarantine
from mesh.semantic_waf import SemanticWaf
from tests.conftest import make_token


def test_scope_encoding_cannot_collide():
    assert Principal("a", tenant_id="a:b", session_id="c").scope_id != Principal("a", tenant_id="a", session_id="b:c").scope_id


@pytest.mark.asyncio
async def test_coarse_state_survives_redis_flush_and_recreation(tmp_path):
    path = tmp_path / "security.db"
    cfg = PolicyConfig()
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    engine = DurableTaintEngine(cfg, DurableState(path), redis)
    async with engine.get_lock("s"):
        assert await engine.evaluate_tool_call("s", "read_file")
    await redis.flushall()
    reopened = DurableTaintEngine(cfg, DurableState(path), redis)
    assert not await reopened.evaluate_tool_call("s", "http_post", {"data": "encoded"})
    assert await reopened.evaluate_tool_call("new-session", "http_post")


@pytest.mark.asyncio
async def test_source_decision_precedes_concurrent_sink(tmp_path):
    engine = DurableTaintEngine(PolicyConfig(), DurableState(tmp_path / "state.db"), fakeredis.aioredis.FakeRedis())
    marked = asyncio.Event()
    async def source():
        async with engine.get_lock("s"):
            assert await engine.evaluate_tool_call("s", "read_file")
            marked.set()
            await asyncio.sleep(.02)
    async def sink():
        await marked.wait()
        async with engine.get_lock("s"):
            return await engine.evaluate_tool_call("s", "http_post")
    assert (await asyncio.gather(source(), sink()))[1] is False


def test_schema_quarantine_survives_restart(tmp_path):
    tool = {"name": "t", "description": "approved", "inputSchema": {}}
    state = DurableState(tmp_path / "s.db")
    first = SchemaLock({"t": compute_hash(tool)})
    first.bind_state(state)
    assert first.check(tool).ok
    assert not first.check({**tool, "description": "changed"}).ok
    second = SchemaLock(first.locks)
    second.bind_state(DurableState(tmp_path / "s.db"))
    assert not second.check(tool).ok
    assert not second.check_call("t").ok


def test_second_worker_is_rejected(tmp_path):
    first, second = SingleWorkerLock(tmp_path), SingleWorkerLock(tmp_path)
    first.acquire()
    try:
        with pytest.raises(RuntimeError): second.acquire()
    finally:
        first.close()
    second.acquire(); second.close()


@pytest.mark.parametrize("case", ["missing", "exception", "oversize"])
def test_dlp_failure_withholds_sensitive_response(case):
    class Broken:
        def find(self, text): raise RuntimeError("model unavailable")
    waf = SemanticWaf(None if case == "missing" else Broken(), max_bytes=10 if case == "oversize" else 1000, fail_closed=True)
    response = waf.scan_egress({"jsonrpc": "2.0", "id": 4, "result": {"secret": "sensitive payload"}})
    assert response["error"]["code"] == -32006 and "sensitive" not in str(response)


def test_audit_failure_prevents_forwarding(build):
    class Broken:
        def append(self, event): raise OSError("disk full")
    app, deps, up, priv = build(roles={"agent-1": ["calculate_math"]}, audit=Broken(), cfg_overrides={"audit_required": True})
    with TestClient(app) as client:
        response = client.post("/rpc", json={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calculate_math"}},
            headers={"Authorization":"Bearer "+make_token(priv)})
    assert response.status_code == 503 and not up.called


def test_backup_restore_integrity_and_fresh_epoch(tmp_path, cfg, rsa_keys):
    source = tmp_path / "original"; source.mkdir()
    initial = initialize(source)
    state = DurableState(source / "security.db"); state.mark("old-session"); state.quarantine("bad-tool")
    with sqlite3.connect(source / "admin.db") as db:
        db.execute("CREATE TABLE roles (id TEXT)"); db.execute("INSERT INTO roles VALUES ('agent')")
    AuditLog(str(source / "audit.log.jsonl")).append({"outcome":"allow"})
    policy, pins = tmp_path / "policy.yaml", tmp_path / "pins.json"
    policy.write_text("security: {}\n"); pins.write_text('{"tools":{}}')
    bundle = tmp_path / "backup.zip"
    backup(source, bundle, policy, pins)
    target = tmp_path / "restored"
    result = restore(bundle, target)
    assert result["epoch"] != initial["epoch"]
    assert DurableState(target / "security.db").contains("old-session")
    assert "bad-tool" in DurableState(target / "security.db").quarantined()
    assert AuditLog.verify(str(target / "audit.log.jsonl"))["ok"]
    verifier = JwtVerifier(cfg); verifier.required_recovery_epoch = result["epoch"]
    with pytest.raises(AuthError): verifier.verify(make_token(rsa_keys[0]))
    with pytest.raises(RuntimeError): restore(bundle, target)


def test_tampered_audit_refuses_resume(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(str(path)).append({"outcome":"allow"})
    path.write_text(path.read_text().replace('"allow"', '"deny"'))
    with pytest.raises(RuntimeError): AuditLog(str(path))


def test_offline_schema_approval_requires_matching_reviewed_pin(tmp_path):
    state = DurableState(tmp_path / "security.db")
    state.quarantine("t")
    AuditLog(str(tmp_path / "audit.log.jsonl")).append({"outcome":"startup"})
    pins = tmp_path / "pins.json"; pins.write_text(json.dumps({"tools":{"t":"a"*64}}))
    with pytest.raises(ValueError): release_quarantine(tmp_path, pins, "t", "b"*64)
    assert "t" in state.quarantined()
    release_quarantine(tmp_path, pins, "t", "a"*64)
    assert "t" not in state.quarantined()
    assert AuditLog.verify(str(tmp_path / "audit.log.jsonl"))["records"] == 2


def test_production_profile_can_disable_legacy_endpoint(build):
    app, _, upstream, priv = build(cfg_overrides={"legacy_rpc_enabled":False})
    with TestClient(app) as client:
        response=client.post("/rpc",json={"jsonrpc":"2.0","id":1,"method":"ping"},headers={"Authorization":"Bearer "+make_token(priv)})
    assert response.status_code == 404 and not upstream.called
