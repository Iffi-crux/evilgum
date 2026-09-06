"""
E1 · Multi-tenant isolation (T-TENANT).

Shared state — taint labels and rate-limit buckets — is keyed by
`Principal.scope_id` = f"{tenant_id}:{session_id}". Two tenants that happen to
mint tokens with the SAME session id (`sid`) must therefore never collide:
tenant A tainting/exhausting a session leaves tenant B's identically-named
session untouched, and every audit record carries the acting tenant.

ISO-01  taint state does not bleed across tenants (same sid)
ISO-02  rate-limit budget is per-tenant (same sid)
ISO-03  a legacy token with no tenant claim collapses to "default" (back-compat)
ISO-04  audit records carry the acting tenant id
ISO-05  scope_id composes tenant + session at the Principal level
"""
import pytest
from starlette.testclient import TestClient

from interceptor.auth import Principal
from tests.conftest import make_token, FakeUpstream, AUD, ISS

TC = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}


def call(c, tok, body, headers=None):
    h = {"authorization": f"Bearer {tok}"}
    if headers:
        h.update(headers)
    return c.post("/rpc", json=body, headers=h)


# ---- ISO-01 · taint isolation --------------------------------------------
def test_iso01_taint_does_not_bleed_across_tenants(build):
    """Tenant A taints a session; tenant B with the SAME sid still gets its
    sink call through — taint labels are tenant-scoped, so no state bleeds."""
    app, deps, up, priv = build(
        roles={"agent-1": ["read_email", "execute_bash"]},
    )
    with TestClient(app) as c:
        # Tenant A: source then sink in one session -> blocked (taint sticks).
        ta = make_token(priv, sub="agent-1", sid="shared-sid", tenant="acme")
        call(c, ta, {**TC, "id": 1, "params": {"name": "read_email", "arguments": {}}})
        ra = call(c, ta, {**TC, "id": 2, "params": {"name": "execute_bash", "arguments": {"cmd": "x"}}})
        assert ra.json()["error"]["code"] == -32001   # A's sink IS blocked

        # Tenant B: SAME sid, but its very first call is the sink -> must pass,
        # because A's taint lives under "acme:shared-sid", not "globex:shared-sid".
        tb = make_token(priv, sub="agent-1", sid="shared-sid", tenant="globex")
        rb = call(c, tb, {**TC, "id": 3, "params": {"name": "execute_bash", "arguments": {"cmd": "x"}}})
        assert rb.json().get("error", {}).get("code") != -32001   # B is NOT tainted


# ---- ISO-02 · rate-limit isolation ---------------------------------------
def test_iso02_rate_limit_is_per_tenant(build):
    """Tenant A exhausts its bucket on a sid; tenant B on the SAME sid still
    has full budget."""
    app, deps, up, priv = build(
        roles={"agent-1": ["read_file"]}, rate_capacity=2, rate_refill=0.0,
    )
    with TestClient(app) as c:
        ta = make_token(priv, sub="agent-1", sid="rl-sid", tenant="acme")
        codes_a = []
        for i in range(5):
            r = call(c, ta, {**TC, "id": i, "params": {"name": "read_file", "arguments": {}}})
            codes_a.append(r.json().get("error", {}).get("code"))
        assert -32005 in codes_a   # A eventually rate-limited

        # Tenant B, same sid, fresh bucket.
        tb = make_token(priv, sub="agent-1", sid="rl-sid", tenant="globex")
        rb = call(c, tb, {**TC, "id": 99, "params": {"name": "read_file", "arguments": {}}})
        assert rb.json().get("error", {}).get("code") != -32005   # B has budget


# ---- ISO-03 · back-compat -------------------------------------------------
def test_iso03_no_tenant_claim_collapses_to_default(build):
    """A legacy token that carries no tenant/org/tid claim must still work and
    land under the 'default' tenant — no behaviour change for single-tenant
    deployments."""
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]})
    with TestClient(app) as c:
        tok = make_token(priv, sub="agent-1", sid="s1")   # no tenant=
        r = call(c, tok, {**TC, "params": {"name": "read_file", "arguments": {}}})
    assert "error" not in r.json() or r.json().get("error") is None


# ---- ISO-04 · audit carries tenant ---------------------------------------
def test_iso04_audit_records_carry_tenant(build):
    class MemAudit:
        def __init__(self):
            self.events = []
        def append(self, event):
            self.events.append(event)

    audit = MemAudit()
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]}, audit=audit)
    with TestClient(app) as c:
        tok = make_token(priv, sub="agent-1", sid="s1", tenant="acme")
        call(c, tok, {**TC, "params": {"name": "read_file", "arguments": {}}})
    assert audit.events, "expected at least one audit record"
    assert any(e.get("tenant") == "acme" for e in audit.events)


# ---- ISO-05 · Principal.scope_id -----------------------------------------
def test_iso05_scope_id_composes_tenant_and_session():
    p = Principal(agent_id="a", session_id="sess-9", tenant_id="acme")
    assert p.scope_id == "acme:sess-9"
    d = Principal(agent_id="a", session_id="sess-9")   # default tenant
    assert d.scope_id == "default:sess-9"
    assert p.scope_id != d.scope_id
