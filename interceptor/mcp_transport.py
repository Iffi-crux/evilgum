"""Bounded stateless JSON profile of MCP 2025-11-25 Streamable HTTP.

This module does not forward caller credentials, sessions, or arbitrary headers.
It deliberately rejects SSE/stateful upstreams instead of bypassing inspection.
"""
from __future__ import annotations

import asyncio
import json

from fastapi import HTTPException, Request

PROTOCOL_VERSION = "2025-11-25"
REQUEST_METHODS = {"initialize", "ping", "tools/list", "tools/call"}


def validate_headers(request: Request, cfg) -> None:
    origin = request.headers.get("origin")
    if origin is not None and origin not in cfg.mcp_allowed_origins:
        raise HTTPException(403, "Origin is not allowed")
    if "mcp-session-id" in request.headers or "last-event-id" in request.headers:
        raise HTTPException(400, "This endpoint supports stateless requests without resumption only")


def validate_message(request: Request, message) -> None:
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "Content-Type must be application/json")
    accepts = {part.split(";", 1)[0].strip().lower() for part in request.headers.get("accept", "").split(",")}
    if not {"application/json", "text/event-stream"} <= accepts:
        raise HTTPException(406, "Accept must include application/json and text/event-stream")
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        raise HTTPException(400, "One JSON-RPC 2.0 message is required; batches are unsupported")
    method = message.get("method")
    if not isinstance(method, str):
        raise HTTPException(400, "Server-initiated requests and client responses are unsupported")
    params = message.get("params", {})
    if not isinstance(params, dict):
        raise HTTPException(400, "params must be an object")
    if method == "notifications/initialized":
        if "id" in message:
            raise HTTPException(400, "Notifications must not have an id")
    elif method in REQUEST_METHODS:
        if type(message.get("id")) not in (str, int):
            raise HTTPException(400, "Requests require a string or integer id")
    else:
        raise HTTPException(400, "Method is outside the supported tools-only profile")
    version = request.headers.get("mcp-protocol-version")
    if method == "initialize":
        if params.get("protocolVersion") != PROTOCOL_VERSION:
            raise HTTPException(400, f"Supported MCP version: {PROTOCOL_VERSION}")
        if params.get("capabilities", {}) != {}:
            raise HTTPException(400, "Client capabilities are unsupported in this stateless profile")
        if version is not None and version != PROTOCOL_VERSION:
            raise HTTPException(400, "Protocol header does not match initialization")
    elif version != PROTOCOL_VERSION:
        raise HTTPException(400, f"MCP-Protocol-Version must be {PROTOCOL_VERSION}")
    if method == "tools/call":
        if not isinstance(params.get("name"), str) or not params["name"]:
            raise HTTPException(400, "Tool name is required")
        if not isinstance(params.get("arguments", {}), dict):
            raise HTTPException(400, "Tool arguments must be an object")
        if "task" in params:
            raise HTTPException(400, "Task-augmented calls are unsupported")


async def forward_json(client, cfg, message):
    """Return a validated RPC response, or None for an accepted notification.

    A total deadline also bounds servers that trickle bytes indefinitely. Limits
    apply to decoded bytes, including compressed responses.
    """
    headers = {"Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": PROTOCOL_VERSION}
    async def exchange():
        async with client.stream("POST", cfg.upstream_url, json=message, headers=headers, follow_redirects=False) as response:
            response.raise_for_status()
            if "mcp-session-id" in response.headers:
                raise ValueError("Stateful upstreams are unsupported")
            if "id" not in message:
                if response.status_code != 202:
                    raise ValueError("Upstream did not acknowledge notification")
                return None
            if response.status_code != 200:
                raise ValueError("Upstream returned no RPC result")
            if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise ValueError("Upstream must use JSON responses; SSE is unsupported")
            chunks, size = [], 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > cfg.mcp_max_response_bytes:
                    raise ValueError("Upstream response exceeds limit")
                chunks.append(chunk)
            payload = json.loads(b"".join(chunks))
            if (not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0"
                    or type(payload.get("id")) is not type(message["id"])
                    or payload.get("id") != message["id"]
                    or ("result" in payload) == ("error" in payload)
                    or "method" in payload):
                raise ValueError("Invalid upstream response envelope")
            if "error" in payload:
                error = payload["error"]
                if not isinstance(error, dict) or type(error.get("code")) is not int or not isinstance(error.get("message"), str):
                    raise ValueError("Invalid upstream error")
            if message["method"] == "initialize" and "result" in payload:
                result = payload["result"]
                if not isinstance(result, dict) or result.get("protocolVersion") != PROTOCOL_VERSION:
                    raise ValueError("Upstream negotiated an unsupported protocol")
                # Do not advertise capabilities for methods this gateway rejects.
                result["capabilities"] = {"tools": {"listChanged": False}}
            return payload
    return await asyncio.wait_for(exchange(), timeout=cfg.mcp_upstream_timeout_seconds)
