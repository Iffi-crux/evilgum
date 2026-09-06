"""
Hardened MCP interceptor pipeline (V6).

Closes, in this one file's control flow:
  AG-02  batch arrays / non-tools-call envelopes are normalized and every element
         runs the FULL pipeline; any policy denial fails the whole request closed.
  AG-03  upstream mTLS verifies the server cert (verify=CA bundle), never verify=False.
  AG-06  request body is capped on BYTES READ from the stream, so a chunked body
         with no Content-Length cannot bypass the limit.
  AG-07  schema-lock enforces by default with real hashing (see schema_lock.py).
  AG-13  alert tasks are referenced so they aren't garbage-collected mid-send.

Built via create_app(cfg, deps) so the adversarial test suite can inject fakes for
Redis, upstream, RBAC and the PII analyzer without external services.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional

import time

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

from interceptor.config import PolicyConfig
from interceptor.auth import JwtVerifier, Principal, AuthError, require_admin
from interceptor.taint import TaintEngine
from interceptor.rbac import RbacEngine
from interceptor.rate_limiter import RedisTokenBucketRateLimiter
from interceptor.schema_lock import SchemaLock
from interceptor.egress_guard import EgressGuard
from mesh.semantic_waf import SemanticWaf
from mesh.sidecar import MacaroonEvaluator, SecurityError

logger = logging.getLogger("gateway.proxy")

# JSON-RPC error codes
E_PARSE = -32700
E_INVALID = -32600
E_RATE = -32005
E_RBAC = -32003
E_TAINT = -32001
E_SCHEMA = -32002
E_WAF = -32000
E_MACAROON = -32004
E_UPSTREAM = -32603


# AG-19: only known JSON-RPC / MCP methods are mediated; anything else fails closed.
KNOWN_METHODS = {
    "initialize", "ping", "tools/list", "tools/call",
    "resources/list", "resources/read", "resources/templates/list",
    "prompts/list", "prompts/get", "completion/complete",
    "logging/setLevel", "roots/list",
    "notifications/initialized", "notifications/cancelled",
}


def fault(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


@dataclass
class Deps:
    verifier: JwtVerifier
    taint: TaintEngine
    rbac: RbacEngine
    rate_limiter: RedisTokenBucketRateLimiter
    waf: SemanticWaf
    schema_lock: SchemaLock
    egress: EgressGuard
    http_client: Any                       # object with async .post(url, json=...)
    macaroon: Optional[MacaroonEvaluator] = None
    alert_hook: Optional[Callable[[str, str], Awaitable[None]]] = None
    admin_router: Any = None
    role_invalidate: Optional[Callable[[str], None]] = None
    audit: Any = None                          # AuditLog instance (tamper-evident log)
    metrics: Any = None                        # MetricsCollector (optional)


async def _read_capped_body(request: Request, max_bytes: int) -> bytes:
    size, chunks = 0, []
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_bytes:
            raise HTTPException(status_code=413, detail="Payload Too Large")
        chunks.append(chunk)
    return b"".join(chunks)


def _is_valid_envelope(obj: Any) -> bool:
    return (isinstance(obj, dict) and obj.get("jsonrpc") == "2.0"
            and isinstance(obj.get("method"), str))


def _params(el: Any) -> Dict[str, Any]:
    """Safely extract params as a dict — malformed clients may send a list/str/null (fuzz-hardened)."""
    p = el.get("params") if isinstance(el, dict) else None
    return p if isinstance(p, dict) else {}


def _args(params: Dict[str, Any]) -> Any:
    a = params.get("arguments")
    return a if a is not None else {}


def create_app(cfg: PolicyConfig, deps: Deps, lifespan=None) -> FastAPI:
    app = FastAPI(title="MCP Interceptor (V6 Hardened)", version="6.0.0", lifespan=lifespan)
    app.state.cfg = cfg
    app.state.deps = deps
    app.state.rbac = deps.rbac
    _alert_tasks: set = set()
    SHADOW = cfg.enforcement_mode == "shadow"   # record would-blocks, never block
    OFF = cfg.enforcement_mode == "off"         # transparent passthrough (incident escape hatch)

    def record(outcome: str, principal, tool, code, detail: str = "") -> None:
        # In shadow mode a policy denial is recorded as "would_<outcome>" so a
        # team can measure impact before turning enforcement on.
        eff = ("would_" + outcome) if (SHADOW and outcome.startswith("deny")) else outcome
        if deps.audit is not None:
            try:
                deps.audit.append({"outcome": eff,
                                   "tenant": getattr(principal, "tenant_id", None),
                                   "agent": getattr(principal, "agent_id", None),
                                   "session": getattr(principal, "session_id", None),
                                   "tool": tool, "code": code, "detail": detail})
            except Exception:
                logger.error("audit append failed")
        if deps.metrics is not None:
            try:
                deps.metrics.decision(eff)
            except Exception:
                pass

    # Backward-compatible alias used by a few call sites.
    audit = record

    def blocks(fault_dict):
        """A policy denial blocks only in enforce mode; in shadow/off it's recorded but let through."""
        return None if (SHADOW or OFF) else fault_dict

    def dispatch_alert(kind: str, details: str) -> None:
        if deps.alert_hook is None:
            return
        task = asyncio.create_task(deps.alert_hook(kind, details))
        _alert_tasks.add(task)                      # hold a reference (AG-13)
        task.add_done_callback(_alert_tasks.discard)

    async def current_principal(request: Request) -> Principal:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        try:
            return deps.verifier.verify(header[7:].strip())
        except AuthError as e:
            raise HTTPException(status_code=401, detail=str(e))

    # ---- admin control plane, gated by the admin SCOPE (not a username) ----
    if deps.admin_router is not None:
        async def admin_guard(principal: Principal = Depends(current_principal)):
            try:
                require_admin(principal, cfg)
            except AuthError as e:
                raise HTTPException(status_code=403, detail=str(e))
            return principal
        app.include_router(deps.admin_router, dependencies=[Depends(admin_guard)])

    async def _authorize_element(principal: Principal, el: Dict[str, Any], macaroon_token: Optional[str]) -> Optional[Dict[str, Any]]:
        """Run non-stateful checks for one element. Returns a fault dict if denied, else None."""
        req_id = el.get("id")
        method = el.get("method")
        if method != "tools/call":
            return None
        params = _params(el)
        tool_name = params.get("name", "")
        arguments = _args(params)

        # WAF ingress (detection only, never mutates what we forward)
        waf_err = deps.waf.inspect_ingress(arguments)
        if waf_err:
            record("deny_waf", principal, tool_name, E_WAF, waf_err)
            d = blocks(fault(req_id, E_WAF, f"ANTI_GRAVITY_INTERCEPT: {waf_err}"))
            if d is not None:
                return d

        # Macaroon: verify signature before trusting caveats
        if macaroon_token:
            try:
                deps.macaroon.verify(macaroon_token) if deps.macaroon else None
            except SecurityError:
                record("deny_macaroon", principal, tool_name, E_MACAROON, "verification failed")
                d = blocks(fault(req_id, E_MACAROON, "ANTI_GRAVITY_INTERCEPT: Macaroon verification failed."))
                if d is not None:
                    return d
        elif cfg.macaroon_required and deps.macaroon is not None:
            record("deny_macaroon", principal, tool_name, E_MACAROON, "required")
            d = blocks(fault(req_id, E_MACAROON, "ANTI_GRAVITY_INTERCEPT: Macaroon required."))
            if d is not None:
                return d

        # RBAC — fail CLOSED if the role store is unreachable (AG-CHAOS).
        try:
            authed = await deps.rbac.is_authorized(principal.agent_id, tool_name)
        except Exception as exc:
            logger.error("RBAC store down, failing closed: %s", exc)
            record("deny_rbac", principal, tool_name, E_RBAC, "store unavailable")
            d = blocks(fault(req_id, E_RBAC, "ANTI_GRAVITY_INTERCEPT: Authorization unavailable — denied (fail-closed)."))
            if d is not None:
                return d
            authed = True   # shadow/off: don't break traffic on infra error
        if not authed:
            record("deny_rbac", principal, tool_name, E_RBAC)
            d = blocks(fault(req_id, E_RBAC, "ANTI_GRAVITY_INTERCEPT: Unauthorized Tool Access."))
            if d is not None:
                return d
        return None

    @app.post("/rpc")
    async def handle_rpc(request: Request, principal: Principal = Depends(current_principal)):
        # Defensive catch-all: no malformed input may produce an unhandled 500 or leak a
        # stack trace. HTTPException (413/401) passes through; anything else fails closed.
        t0 = time.perf_counter()
        try:
            return await _rpc_impl(request, principal)
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("unhandled error in /rpc, failing closed: %s", exc)
            return JSONResponse(fault(None, E_INVALID, "ANTI_GRAVITY_INTERCEPT: malformed request rejected."), status_code=400)
        finally:
            if deps.metrics is not None:
                try:
                    deps.metrics.observe_latency(time.perf_counter() - t0)
                except Exception:
                    pass

    async def _rpc_impl(request: Request, principal: Principal):
        session_id = principal.scope_id      # tenant-scoped: taint + rate-limit never collide across tenants
        if deps.metrics is not None:
            deps.metrics.request()

        body = await _read_capped_body(request, cfg.max_body_bytes)

        # AG-CHAOS: fail CLOSED if the rate-limit backend (Redis) is unreachable.
        # In OFF (incident passthrough) the limiter is skipped entirely.
        if not OFF:
            try:
                rl_ok = await deps.rate_limiter.consume(session_id)
            except Exception as exc:
                logger.error("rate-limit backend down, failing closed: %s", exc)
                d = blocks(fault(None, E_RATE, "ANTI_GRAVITY_INTERCEPT: Limiter unavailable — denied (fail-closed)."))
                if d is not None:
                    return JSONResponse(d, status_code=503)
                rl_ok = True
            if not rl_ok:
                record("deny_rate", principal, None, E_RATE)
                d = blocks(fault(None, E_RATE, "ANTI_GRAVITY_INTERCEPT: Rate Limit Exceeded."))
                if d is not None:
                    return JSONResponse(d)

        import json
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return JSONResponse(fault(None, E_PARSE, "Parse error"), status_code=400)

        # AG-02: normalize single object AND batch array; validate every envelope.
        is_batch = isinstance(parsed, list)
        elements: List[Any] = parsed if is_batch else [parsed]
        if not elements or not all(_is_valid_envelope(e) for e in elements):
            return JSONResponse(fault(None, E_INVALID, "Invalid JSON-RPC envelope"), status_code=400)

        # AG-19: reject unknown methods (fail closed) so nothing unmediated is forwarded.
        if cfg.method_allowlist_enforce:
            for el in elements:
                if el.get("method") not in KNOWN_METHODS:
                    return JSONResponse(fault(el.get("id"), E_INVALID,
                        f"ANTI_GRAVITY_INTERCEPT: method '{el.get('method')}' not permitted."), status_code=400)

        macaroon_token = request.headers.get("x-mcp-macaroon")

        # Pass 1: stateless checks (WAF, macaroon, RBAC) for every element.
        # Skipped wholesale only in OFF (incident passthrough); in shadow the
        # checks run and record would-blocks but never return a denial.
        if not OFF:
            for el in elements:
                denial = await _authorize_element(principal, el, macaroon_token)
                if denial is not None:
                    return JSONResponse(denial)   # fail closed; nothing forwarded

        # Pass 2: taint gate for tool_call elements, in order, under one session lock.
        tool_calls = [e for e in elements if e.get("method") == "tools/call"]
        if tool_calls and not OFF:
            try:
                lock_cm = deps.taint.get_lock(session_id)
                async with lock_cm:
                    denied_el = None
                    for el in tool_calls:
                        params = _params(el)
                        name = params.get("name", "")
                        permitted = await deps.taint.evaluate_tool_call(session_id, name, params.get("arguments"))
                        if not permitted:
                            denied_el = el
                            break
            except Exception as exc:
                logger.error("taint backend down, failing closed: %s", exc)
                return JSONResponse(fault(None, E_TAINT, "ANTI_GRAVITY_INTERCEPT: IFC engine unavailable — denied (fail-closed)."), status_code=503)
            if denied_el is not None:
                denied_name = _params(denied_el).get("name", "")
                msg = f"Tainted session '{session_id}' attempted sink '{denied_name}'."
                dispatch_alert("DataExfiltrationAttempt", msg)
                record("deny_taint", principal, denied_name, E_TAINT, msg)
                d = blocks(fault(denied_el.get("id"), E_TAINT,
                    "ANTI_GRAVITY_INTERCEPT: Cross-boundary exfiltration attempt blocked."))
                if d is not None:
                    return JSONResponse(d)

        # Forward upstream over verified mTLS (AG-03). Payload is unchanged (AG-08).
        try:
            upstream_resp = await deps.http_client.post(cfg.upstream_url, json=parsed)
            upstream_resp.raise_for_status()
            rpc_resp = upstream_resp.json()
        except Exception as exc:
            logger.error("Upstream failed: %s", exc)
            return JSONResponse(fault(None, E_UPSTREAM, "ANTI_GRAVITY_INTERCEPT: Upstream MCP server unreachable."))

        # Post-process (handle batch or single response symmetrically).
        resp_list = rpc_resp if isinstance(rpc_resp, list) else [rpc_resp]

        # Value-level IFC (R9): fingerprint what source tools returned so a later
        # sink carrying that data can be blocked precisely.
        if cfg.taint_mode == "value":
            by_id = {r.get("id"): r for r in resp_list if isinstance(r, dict)}
            for el in tool_calls:
                name = _params(el).get("name", "")
                if cfg.is_source(name):
                    r = by_id.get(el.get("id"))
                    if r and isinstance(r, dict) and "result" in r:
                        await deps.taint.capture_source_output(session_id, r["result"])

        out = [await self_post_process(el, principal, deps, cfg, dispatch_alert) for el in resp_list]
        record("allow", principal, ",".join(_params(e).get("name", "") for e in tool_calls) or None, 0)
        return JSONResponse(out if isinstance(rpc_resp, list) else out[0])

    # ---- operational endpoints (HA + observability), all unauthenticated ----
    @app.get("/healthz")
    async def healthz():
        """Liveness: the process is up and serving. Never touches dependencies."""
        return {"status": "ok", "mode": cfg.enforcement_mode}

    @app.get("/readyz")
    async def readyz():
        """Readiness: the shared state backend (Redis) is reachable, so this
        replica can safely take traffic behind a load balancer. Fail = pull it
        out of rotation, don't send it requests."""
        checks: Dict[str, str] = {}
        ok = True
        try:
            rc = getattr(deps.rate_limiter, "redis", None)
            if rc is not None and hasattr(rc, "ping"):
                await rc.ping()
            checks["redis"] = "ok"
        except Exception as exc:
            ok = False
            checks["redis"] = f"unreachable: {exc.__class__.__name__}"
        status = 200 if ok else 503
        return JSONResponse({"status": "ready" if ok else "not-ready", "checks": checks}, status_code=status)

    if cfg.metrics_enabled and deps.metrics is not None:
        @app.get("/metrics")
        async def metrics_endpoint():
            return PlainTextResponse(deps.metrics.render(), media_type="text/plain; version=0.0.4")

    return app


async def self_post_process(rpc_resp: Dict[str, Any], principal: Principal, deps: Deps,
                            cfg: PolicyConfig, dispatch_alert) -> Dict[str, Any]:
    if not isinstance(rpc_resp, dict):
        return rpc_resp
    if "error" in rpc_resp:
        return deps.egress.sanitize_error(rpc_resp)

    result = rpc_resp.get("result")
    # tools/list: schema-lock (AG-07) + RBAC filtering, in a single pass.
    if isinstance(result, dict) and "tools" in result:
        allowed = await deps.rbac.allowed_tools(principal.agent_id)
        filtered = []
        for tool in result["tools"]:
            verdict = deps.schema_lock.check(tool)
            if not verdict.ok:
                dispatch_alert("SchemaDriftRugPull", verdict.reason)
                return fault(rpc_resp.get("id"), E_SCHEMA, f"ANTI_GRAVITY_INTERCEPT: {verdict.reason}")
            name = tool.get("name")
            if "*" in allowed or name in allowed:
                filtered.append(tool)
        result["tools"] = filtered
        return rpc_resp

    # tools/call response: egress redaction (AG-09)
    return deps.waf.scan_egress(rpc_resp)
