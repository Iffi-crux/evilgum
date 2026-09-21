"""Official SDK over real loopback TCP, through the production policy pipeline."""
import asyncio
import socket
from contextlib import asynccontextmanager
from datetime import timedelta

import httpx
import anyio
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP
from mcp.shared.exceptions import McpError

from interceptor.schema_lock import compute_hash
from tests.conftest import make_token

VERSION = "2025-11-25"


@asynccontextmanager
async def serve(app):
    """Pre-bind to an OS-assigned port; no port-selection race or external service."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        with anyio.fail_after(10):
            while not server.started:
                if task.done():
                    await task
                    raise RuntimeError("test server exited before startup")
                await asyncio.sleep(0.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, 10)
        finally:
            sock.close()


@pytest.mark.asyncio
async def test_official_sdk_discovery_calls_denials_and_reconnect(build):
    backend = FastMCP("beta-test", stateless_http=True, json_response=True)
    executed = []

    @backend.tool()
    def calculate_math(a: int, b: int) -> int:
        """Add two integers."""
        executed.append("calculate_math")
        return a + b

    @backend.tool()
    def execute_bash(command: str) -> str:
        """A test-only sink that records invocation; never executes a command."""
        executed.append("execute_bash")
        return command

    @backend.tool()
    def read_file() -> str:
        """Return synthetic source data without reading a real file."""
        executed.append("read_file")
        return "synthetic-source-data"

    @backend.tool()
    def http_post(value: str) -> str:
        """Record a synthetic sink without performing a network request."""
        executed.append("http_post")
        return value

    definitions = await backend.list_tools()
    pins = {tool.name: compute_hash(tool.model_dump(by_alias=True, exclude_none=True)) for tool in definitions}
    requests = []
    async def capture(request):
        requests.append(request)

    async with serve(backend.streamable_http_app()) as upstream_url:
        async with httpx.AsyncClient(event_hooks={"request": [capture]}, timeout=5) as upstream:
            app, deps, _, priv = build(roles={"agent-1": ["calculate_math", "read_file", "http_post"]}, upstream=upstream,
                schema_locks=pins, cfg_overrides={"upstream_url": upstream_url + "/mcp"})
            async with serve(app) as gateway_url:
                headers = {"Authorization": "Bearer " + make_token(priv)}
                # Two independent SDK connections verify stateless reconnect behavior.
                for attempt in range(2):
                    async with httpx.AsyncClient(headers=headers, timeout=5) as client:
                        async with streamable_http_client(gateway_url + "/mcp", http_client=client) as (read, write, get_sid):
                            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=5)) as session:
                                init = await session.initialize()
                                assert init.protocolVersion == VERSION
                                assert init.capabilities.resources is None
                                assert init.capabilities.prompts is None
                                assert get_sid() is None
                                if attempt == 0:
                                    with pytest.raises(McpError) as unverified:
                                        await session.call_tool("calculate_math", {"a": 2, "b": 3})
                                    assert unverified.value.error.code == -32002
                                listing = await session.list_tools()
                                assert {t.name for t in listing.tools} == {"calculate_math", "read_file", "http_post"}
                                result = await session.call_tool("calculate_math", {"a": 2, "b": 3})
                                assert not result.isError and result.content[0].text == "5"
                                with pytest.raises(McpError) as denied:
                                    await session.call_tool("execute_bash", {"command": "test"})
                                assert denied.value.error.code == -32003
                                source = await session.call_tool("read_file", {})
                                assert source.content[0].text == "synthetic-source-data"
                                with pytest.raises(McpError) as tainted:
                                    await session.call_tool("http_post", {"value": "synthetic-source-data"})
                                assert tainted.value.error.code == -32001
                assert executed == ["calculate_math", "read_file", "calculate_math", "read_file"]
                assert all("authorization" not in r.headers for r in requests)
                assert all(r.headers["mcp-protocol-version"] == VERSION for r in requests)
                assert any(b"notifications/initialized" in r.content for r in requests)


@pytest.mark.asyncio
async def test_initialized_notification_returns_empty_202(build):
    backend = FastMCP("notifications", stateless_http=True, json_response=True)
    async with _backend_app(backend) as backend_app:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=backend_app), base_url="http://localhost:8000") as upstream:
            app, _, _, priv = build(upstream=upstream, cfg_overrides={"upstream_url": "http://localhost:8000/mcp"})
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway") as client:
                response = await client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                    headers={"Authorization": "Bearer " + make_token(priv), "MCP-Protocol-Version": VERSION,
                             "Accept": "application/json, text/event-stream"})
                assert response.status_code == 202 and response.content == b""


@asynccontextmanager
async def _backend_app(backend):
    app = backend.streamable_http_app()
    async with app.router.lifespan_context(app):
        yield app
