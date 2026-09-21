# MCP compatibility: first verified configuration

Verified locally on 2026-09-21 with Python 3.12 and official MCP Python SDK **1.26.0** at both ends of a real loopback HTTP connection.

| Component | Supported configuration |
|---|---|
| Gateway endpoint | `POST /mcp` |
| Protocol revision | `2025-11-25` only |
| Upstream | Streamable HTTP, stateless, JSON responses |
| Official Python server settings | `FastMCP(..., stateless_http=True, json_response=True)` |
| Methods | `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call` |
| Identity | Signed gateway Bearer JWT; existing tenant/role rules apply |
| Client capabilities | Empty capability object; no server-to-client requests |
| GET / DELETE | Authenticated, returns 405; no standalone event stream/session termination |
| Legacy endpoint | `/rpc` is disabled in production; development adapter is outside this verified MCP profile |

This is a scoped compatibility result, not certification for every MCP host. Claude Desktop, Cursor, other SDKs, stdio, stateful upstreams, SSE, resumable streams, cancellation, sampling, elicitation, tasks and protocol revision 2026-07-28 are not verified/supported by this profile. Unsupported streaming/session traffic fails closed; it is not passed through uninspected.

## Repeat the verification

From the core repository, in a virtual environment:

```sh
python -m pip install -e ".[dev,integration]"
python -m pytest tests/test_mcp_transport.py tests/test_mcp_boundary.py -q
python -m pytest -q
```

The integration extra pins the official SDK and its SSE helper used by the test server. This is not a full transitive dependency lock; reproducible clean installation remains a separate launch gate.

The tests start two real HTTP servers on OS-assigned loopback ports and stop them afterwards. Redis and role storage are test fixtures. No real files, shell commands, outgoing sink requests, external services, customer data or production credentials are used by the test tools.

Verified: initialization, matching protocol headers, empty 202 notification acknowledgement, filtered discovery, allowed execution, schema approval before first call, RBAC denial, taint denial, and a fresh connection. No gateway Bearer token is forwarded upstream. Reconnection here means a new stateless client connection, not event replay. JWT session claims still scope taint/rate state; reconnecting does not clear that state.

Negative tests cover invalid Origins, unsupported methods/versions/session headers, batch bodies, malformed envelopes, unexpected response IDs, invalid JSON, HTTP failures, redirects, response size limits, timeouts and SSE rejection. Upstream transport failures return sanitized HTTP 502 responses; policy denials retain the requested JSON-RPC ID.

## Connect to a configured gateway

1. Configure `UPSTREAM_MCP_URL` to the actual upstream MCP endpoint, with stateless JSON mode enabled. Keep upstream TLS verification and the existing production identity settings enabled.
2. Install reviewed schema hashes in `mcp-lock.json`. Keep schema enforcement on and learning off. Grant the caller's tools using the tenant-scoped admin API.
3. Set `GATEWAY_TOKEN` in your local environment to a signed JWT with the intended tenant, subject and session. Do not put tokens in URLs or command arguments.
4. Run the discovery-only smoke client:

```sh
python examples/mcp_smoke_client.py --url https://your-gateway.example/mcp
```

The script initializes and lists permitted tools; it executes no tools. This command assumes a configured gateway already exists. It does not deploy one or fix the remaining container storage prerequisites.

The endpoint requires `Content-Type: application/json` and `Accept: application/json, text/event-stream`. Initialization must request version 2025-11-25; later requests must include `MCP-Protocol-Version: 2025-11-25`. The pinned official client supplies these headers.

`MCP_ALLOWED_ORIGINS` is an optional comma-separated list of exact browser origins (scheme, host and port). The default rejects every request carrying an Origin header; native clients without that header can authenticate normally. This does not enable browser CORS support.

`MCP_MAX_RESPONSE_BYTES` defaults to 1 MiB of decoded response data; `MCP_UPSTREAM_TIMEOUT_SECONDS` defaults to a 30-second total exchange deadline. SSE responses are rejected before their bodies are consumed. Caller session IDs, replay cursors, Origins and authorization headers are not copied to the upstream request. Existing configured upstream mTLS is the upstream identity mechanism.

## Release status

Core suite: **153 passed, 1 expected failure**. Transport subset: **34 passed**. The expected failure is the pre-existing re-encoded-data bypass in optional value tracking, not a transport failure. SDK/Pydantic settings emits a warning in the test environment; no test fails because of it.

Production storage/restart/backup validation and reproducible installation are still open. Do not turn this local compatibility result into a general availability claim.

Sources: [MCP 2025-11-25 transport specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/basic/transports.mdx), [official Python SDK v1.26.0](https://github.com/modelcontextprotocol/python-sdk/tree/v1.26.0).
