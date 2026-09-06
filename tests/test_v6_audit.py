"""Tamper-evident audit log tests (MCP08)."""
import json
import pytest
from starlette.testclient import TestClient
from interceptor.audit import AuditLog
from tests.conftest import make_token

TC = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}


def test_audit_chain_verifies(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    for i in range(5):
        log.append({"outcome": "allow", "i": i})
    v = AuditLog.verify(str(tmp_path / "a.jsonl"))
    assert v["ok"] is True and v["records"] == 5


def test_audit_tamper_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(str(p))
    for i in range(5):
        log.append({"outcome": "allow", "i": i})
    # Attacker edits record #2's event in place.
    lines = p.read_text().splitlines()
    rec = json.loads(lines[2]); rec["event"]["outcome"] = "deny"; lines[2] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    v = AuditLog.verify(str(p))
    assert v["ok"] is False and v["broken_at_line"] == 3


def test_audit_resumes_chain_across_reopen(tmp_path):
    p = str(tmp_path / "a.jsonl")
    AuditLog(p).append({"outcome": "allow", "n": 1})
    AuditLog(p).append({"outcome": "deny", "n": 2})   # reopened, must continue the chain
    v = AuditLog.verify(p)
    assert v["ok"] is True and v["records"] == 2


def test_proxy_logs_denials_and_allows(build, tmp_path):
    log = AuditLog(str(tmp_path / "gw.jsonl"))
    app, deps, up, priv = build(roles={"agent-1": ["read_file"]}, audit=log)
    tok = make_token(priv, sub="agent-1")
    with TestClient(app) as c:
        # allowed
        c.post("/rpc", json={**TC, "params": {"name": "read_file", "arguments": {}}},
               headers={"authorization": f"Bearer {tok}"})
        # denied (RBAC)
        c.post("/rpc", json={**TC, "id": 2, "params": {"name": "execute_bash", "arguments": {}}},
               headers={"authorization": f"Bearer {tok}"})
    outcomes = [json.loads(l)["event"]["outcome"] for l in open(str(tmp_path / "gw.jsonl"))]
    assert "allow" in outcomes and "deny_rbac" in outcomes
    assert AuditLog.verify(str(tmp_path / "gw.jsonl"))["ok"] is True
