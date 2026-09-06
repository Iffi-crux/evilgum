"""
Tier-2 + R9 verification: AG-14, AG-19, and value-level taint (AG-05 deep fix).
"""
from starlette.testclient import TestClient
from tests.conftest import make_token, FakeUpstream

TOOLS_CALL = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}


def call(client, token, body, headers=None):
    h = {"authorization": f"Bearer {token}"}
    if headers:
        h.update(headers)
    return client.post("/rpc", json=body, headers=h)


# ---------------- AG-19: method allowlist ----------------
def test_ag19_unknown_method_rejected_and_not_forwarded(build):
    app, deps, up, priv = build(roles={"agent-1": ["*"]})
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        r = call(c, tok, {"jsonrpc": "2.0", "id": 1, "method": "evil/backdoor", "params": {}})
    assert r.status_code == 400
    assert up.called is False


def test_ag19_known_method_allowed(build):
    up = FakeUpstream({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
    app, deps, up, priv = build(roles={"agent-1": ["*"]}, upstream=up)
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        r = call(c, tok, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert "error" not in r.json()


# ---------------- AG-14: DLP safety ----------------
class FailingPii:
    def find(self, text):
        raise RuntimeError("model exploded")


def test_ag14_dlp_analyzer_failure_does_not_crash(build):
    up = FakeUpstream({"jsonrpc": "2.0", "id": 1, "result": {"note": "hello"}})
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]}, upstream=up, pii=FailingPii())
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        r = call(c, tok, {**TOOLS_CALL, "params": {"name": "read_file", "arguments": {}}})
    assert r.status_code == 200
    assert r.json()["result"]["note"] == "hello"


def test_ag14_dlp_can_be_disabled(build):
    from tests.conftest import StubPii
    up = FakeUpstream({"jsonrpc": "2.0", "id": 1, "result": {"card": "4111111111111111"}})
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]}, upstream=up, pii=StubPii(),
                                cfg_overrides={"dlp_egress_enabled": False})
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        r = call(c, tok, {**TOOLS_CALL, "params": {"name": "read_file", "arguments": {}}})
    assert r.json()["result"]["card"] == "4111111111111111"  # not scanned when disabled


# ---------------- R9: value-level taint ----------------
def _secret_upstream(req):
    """read_email returns a secret; everything else returns ok."""
    method = req.get("method")
    name = (req.get("params") or {}).get("name")
    if method == "tools/call" and name == "read_email":
        return {"jsonrpc": "2.0", "id": req.get("id"), "result": {"body": "SECRETTOKEN123"}}
    return {"jsonrpc": "2.0", "id": req.get("id"), "result": {"ok": True}}


def test_r9_value_mode_blocks_sink_carrying_tainted_data(build):
    up = FakeUpstream(_secret_upstream)
    app, deps, up, priv = build(roles={"agent-1": ["read_email", "http_post"]}, upstream=up,
                                cfg_overrides={"taint_mode": "value"})
    tok = make_token(priv, sub="agent-1", sid="vs1")
    with TestClient(app) as c:
        r1 = call(c, tok, {**TOOLS_CALL, "params": {"name": "read_email", "arguments": {}}})
        assert "error" not in r1.json()
        # Now try to exfiltrate the exact secret via a sink.
        r2 = call(c, tok, {**TOOLS_CALL, "id": 2,
                           "params": {"name": "http_post", "arguments": {"data": "SECRETTOKEN123"}}})
    assert r2.json()["error"]["code"] == -32001


def test_r9_value_mode_allows_sink_without_tainted_data(build):
    """Precision: a tainted session may still make an UNRELATED sink call."""
    up = FakeUpstream(_secret_upstream)
    app, deps, up, priv = build(roles={"agent-1": ["read_email", "execute_bash"]}, upstream=up,
                                cfg_overrides={"taint_mode": "value"})
    tok = make_token(priv, sub="agent-1", sid="vs2")
    with TestClient(app) as c:
        call(c, tok, {**TOOLS_CALL, "params": {"name": "read_email", "arguments": {}}})
        r = call(c, tok, {**TOOLS_CALL, "id": 2,
                          "params": {"name": "execute_bash", "arguments": {"cmd": "ls -la"}}})
    assert "error" not in r.json()   # no tainted data in args -> allowed (no false positive)


def test_r9_coarse_mode_still_default_blocks(build):
    """Default coarse mode is unchanged: any sink after a source is blocked."""
    up = FakeUpstream(_secret_upstream)
    app, deps, up, priv = build(roles={"agent-1": ["read_email", "execute_bash"]}, upstream=up)
    tok = make_token(priv, sub="agent-1", sid="cs1")
    with TestClient(app) as c:
        call(c, tok, {**TOOLS_CALL, "params": {"name": "read_email", "arguments": {}}})
        r = call(c, tok, {**TOOLS_CALL, "id": 2,
                          "params": {"name": "execute_bash", "arguments": {"cmd": "ls"}}})
    assert r.json()["error"]["code"] == -32001
