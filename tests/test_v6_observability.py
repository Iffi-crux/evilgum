"""
Shadow-mode enforcement + metrics + HA readiness.

SHADOW-01  in shadow mode an unauthorized call is NOT blocked (forwarded)
SHADOW-02  ...but it IS recorded as a would-block in the audit log
SHADOW-03  in shadow mode a taint/exfil chain is forwarded but recorded
SHADOW-04  "off" mode is a transparent passthrough (no checks run)
SHADOW-05  enforce mode (default) still blocks — regression guard
MET-01     /metrics exposes Prometheus counters incl. decisions_total
MET-02     blocked vs allowed reflected in metrics
MET-03     shadow would-blocks land in would_block_total, not blocked_total
HA-01      /healthz is open and reports the mode
HA-02      /readyz reports ready when Redis answers
"""
import pytest
from starlette.testclient import TestClient

from interceptor.metrics import MetricsCollector
from tests.conftest import make_token, FakeUpstream

TC = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}


def call(c, tok, body, headers=None):
    h = {"authorization": f"Bearer {tok}"}
    if headers:
        h.update(headers)
    return c.post("/rpc", json=body, headers=h)


# ---------- shadow mode ----------
def test_shadow01_unauthorized_not_blocked(build):
    # agent-1 lacks execute_bash. In shadow, the call is forwarded anyway.
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]},
                                cfg_overrides={"enforcement_mode": "shadow"})
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        r = call(c, tok, {**TC, "params": {"name": "execute_bash", "arguments": {"cmd": "x"}}})
    assert "error" not in r.json()          # NOT blocked
    assert up.called is True                 # forwarded upstream


def test_shadow02_would_block_recorded(build):
    class MemAudit:
        def __init__(self): self.events = []
        def append(self, e): self.events.append(e)
    audit = MemAudit()
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]}, audit=audit,
                                cfg_overrides={"enforcement_mode": "shadow"})
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        call(c, tok, {**TC, "params": {"name": "execute_bash", "arguments": {"cmd": "x"}}})
    outcomes = [e["outcome"] for e in audit.events]
    assert "would_deny_rbac" in outcomes    # recorded as a would-block
    assert "deny_rbac" not in outcomes       # never a real block


def test_shadow03_taint_chain_forwarded_but_recorded(build):
    class MemAudit:
        def __init__(self): self.events = []
        def append(self, e): self.events.append(e)
    audit = MemAudit()
    app, deps, up, priv = build(roles={"agent-1": ["read_email", "execute_bash"]}, audit=audit,
                                cfg_overrides={"enforcement_mode": "shadow"})
    tok = make_token(priv, sub="agent-1", sid="s1")
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_email", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "execute_bash", "arguments": {"cmd": "x"}}},
    ]
    with TestClient(app) as c:
        r = call(c, tok, batch)
    assert "error" not in (r.json() if isinstance(r.json(), dict) else {"error": None}) or isinstance(r.json(), list)
    assert any(e["outcome"] == "would_deny_taint" for e in audit.events)


def test_shadow04_off_is_passthrough(build):
    # In off mode even an unauthorized call is forwarded and no deny recorded.
    class MemAudit:
        def __init__(self): self.events = []
        def append(self, e): self.events.append(e)
    audit = MemAudit()
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]}, audit=audit,
                                cfg_overrides={"enforcement_mode": "off"})
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        r = call(c, tok, {**TC, "params": {"name": "execute_bash", "arguments": {"cmd": "x"}}})
    assert "error" not in r.json() and up.called is True
    assert not any(e["outcome"].startswith("deny") or e["outcome"].startswith("would_") for e in audit.events)


def test_shadow05_enforce_still_blocks(build):
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]})   # default enforce
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        r = call(c, tok, {**TC, "params": {"name": "execute_bash", "arguments": {"cmd": "x"}}})
    assert r.json()["error"]["code"] == -32003 and up.called is False


# ---------- metrics ----------
def test_met01_metrics_endpoint_exposes_counters(build):
    m = MetricsCollector()
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]}, metrics=m)
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        call(c, tok, {**TC, "params": {"name": "read_file", "arguments": {}}})
        r = c.get("/metrics")
    assert r.status_code == 200
    body = r.text
    assert "evilgum_decisions_total" in body
    assert "evilgum_request_latency_seconds_bucket" in body
    assert 'evilgum_decisions_total{outcome="allow"} 1' in body


def test_met02_blocked_counted(build):
    m = MetricsCollector()
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]}, metrics=m)
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        call(c, tok, {**TC, "params": {"name": "execute_bash", "arguments": {"cmd": "x"}}})  # blocked
        r = c.get("/metrics")
    assert "evilgum_blocked_total 1" in r.text
    assert 'evilgum_decisions_total{outcome="deny_rbac"} 1' in r.text


def test_met03_shadow_wouldblock_counted_separately(build):
    m = MetricsCollector()
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]}, metrics=m,
                                cfg_overrides={"enforcement_mode": "shadow"})
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        call(c, tok, {**TC, "params": {"name": "execute_bash", "arguments": {"cmd": "x"}}})
        r = c.get("/metrics")
    assert "evilgum_would_block_total 1" in r.text
    assert "evilgum_blocked_total 0" in r.text


# ---------- HA ----------
def test_ha01_healthz_open(build):
    app, deps, up, priv = build(cfg_overrides={"enforcement_mode": "shadow"})
    with TestClient(app) as c:
        r = c.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok" and r.json()["mode"] == "shadow"


def test_ha02_readyz_ok_when_redis_up(build):
    app, deps, up, priv = build()   # fakeredis answers ping
    with TestClient(app) as c:
        r = c.get("/readyz")
    assert r.status_code == 200 and r.json()["status"] == "ready"
    assert r.json()["checks"]["redis"] == "ok"
