"""Negative transport tests: unsupported traffic must never escape inspection."""
import asyncio
import httpx
import pytest

from tests.conftest import make_token

PING = {"jsonrpc": "2.0", "id": "probe", "method": "ping"}
HEADERS = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"}


@pytest.mark.asyncio
@pytest.mark.parametrize("body,extra,status", [
    ([PING], {}, 400),
    ({**PING, "id": None}, {}, 400),
    ({**PING, "id": True}, {}, 400),
    ({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "calculate_math"}}, {}, 400),
    ({**PING, "method": "notifications/initialized"}, {}, 400),
    ({**PING, "method": "notifications/cancelled"}, {}, 400),
    ({**PING, "method": "tools/call", "params": {"name": "calculate_math", "arguments": []}}, {}, 400),
    ({**PING, "method": "tools/call", "params": {"name": "calculate_math", "task": {}}}, {}, 400),
    ({**PING, "method": "resources/read"}, {}, 400),
    (PING, {"MCP-Protocol-Version": "2026-07-28"}, 400),
    (PING, {"MCP-Protocol-Version": ""}, 400),
    (PING, {"MCP-Session-Id": "another-customer"}, 400),
    (PING, {"Last-Event-ID": "another-stream"}, 400),
    (PING, {"Origin": "https://untrusted.example"}, 403),
    (PING, {"Origin": "null"}, 403),
    (PING, {"Accept": "application/json"}, 406),
    (PING, {"Content-Type": "text/plain"}, 415),
    ({**PING, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}, {}, 400),
    ({**PING, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {"sampling": {}}}}, {}, 400),
])
async def test_unsupported_requests_never_forward(build, body, extra, status):
    app, deps, upstream, priv = build()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway") as client:
        response = await client.post("/mcp", json=body,
            headers={**HEADERS, "Authorization": "Bearer " + make_token(priv), **extra})
    assert response.status_code == status
    assert not upstream.called


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["sse", "session", "mismatch", "version", "oversize", "malformed", "timeout", "error", "redirect", "empty"])
async def test_upstream_failure_is_bounded_and_sanitized(build, case):
    async def handler(request):
        if case == "timeout":
            await asyncio.sleep(1)
        if case == "sse":
            return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, text="data: SECRET\n\n")
        if case == "oversize":
            return httpx.Response(200, headers={"Content-Type": "application/json"}, text="x" * 200)
        if case == "malformed":
            return httpx.Response(200, headers={"Content-Type": "application/json"}, text="SECRET")
        if case == "error":
            return httpx.Response(500, text="SECRET")
        if case == "redirect":
            return httpx.Response(302, headers={"Location": "https://untrusted.example"})
        if case == "empty":
            return httpx.Response(202)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "wrong" if case == "mismatch" else "probe",
            "result": {"protocolVersion": "wrong"} if case == "version" else {}},
            headers={"MCP-Session-Id": "SECRET"} if case == "session" else {})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as upstream:
        app, _, _, priv = build(upstream=upstream, cfg_overrides={"mcp_max_response_bytes": 100,
                                                               "mcp_upstream_timeout_seconds": 0.1})
        body = PING if case != "version" else {**PING, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway") as client:
            response = await client.post("/mcp", json=body, headers={**HEADERS, "Authorization": "Bearer " + make_token(priv)})
        assert response.status_code == 502
        assert response.json()["id"] == "probe"
        assert "SECRET" not in response.text and "mcp-session-id" not in response.headers


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_stream_methods_authenticate_then_explicitly_reject(build, method):
    app, _, upstream, priv = build()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway") as client:
        assert (await client.request(method, "/mcp")).status_code == 401
        headers = {"Authorization": "Bearer " + make_token(priv)}
        assert (await client.request(method, "/mcp", headers=headers)).status_code == 405
        assert (await client.request(method, "/mcp", headers={**headers, "Origin": "https://untrusted.example"})).status_code == 403
    assert not upstream.called


@pytest.mark.asyncio
async def test_explicit_allowed_origin_and_sanitized_rpc_error(build):
    async def handler(request):
        assert "origin" not in request.headers
        assert "authorization" not in request.headers
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "probe",
            "error": {"code": -32602, "message": "SECRET", "data": "SECRET"}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as upstream:
        app, _, _, priv = build(upstream=upstream, cfg_overrides={"mcp_allowed_origins": {"https://trusted.example"}})
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway") as client:
            response = await client.post("/mcp", json=PING, headers={**HEADERS,
                "Authorization": "Bearer " + make_token(priv), "Origin": "https://trusted.example"})
        assert response.status_code == 200
        assert response.json()["error"]["code"] == -32602
        assert "SECRET" not in response.text
