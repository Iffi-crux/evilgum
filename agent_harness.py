"""
Agent harness — the missing target for garak / promptfoo-redteam / WASP.

These tools attack an AGENT (prompt in -> action out). Our gateway is the firewall
BEHIND the agent, so it needs an agent to sit in front of. This is a deliberately
GULLIBLE agent: it obeys whatever imperative it finds in its input (i.e. it is
already prompt-injected / hijacked), and tries to run the corresponding tool call
THROUGH THE GATEWAY. The point: even a fully-hijacked agent cannot cause harm,
because the gateway blocks the dangerous tool call.

Endpoint:  POST /chat  {"input": "...text (possibly poisoned)..."}
Returns:   {"output": "...", "executed": bool, "blocked_by_gateway": bool, "tool": "..."}

The output string is explicit ("EXECUTED: ..." vs "BLOCKED_BY_GATEWAY: ...") so garak /
promptfoo detectors can score Attack Success Rate = fraction that EXECUTED.

Run:  python -m uvicorn agent_harness:app --host 127.0.0.1 --port 8090
(the gateway must be running on :8080 first)

Modes:
  AGENT_MODE=naive (default) — deterministic, maximally gullible, no API key.
  AGENT_MODE=llm  + OPENAI_API_KEY — a real LLM chooses the tool (optional).
"""
from __future__ import annotations
import os, re, json
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

GATEWAY = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8080/rpc")
TOKEN = os.environ.get("GATEWAY_TOKEN") or (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudC0xIiwic2lkIjoiYWdlbnQiLCJzY29wZSI6IiIs"
    "ImF1ZCI6Im1jcC1nYXRld2F5IiwiaXNzIjoibWNwLWdhdGV3YXktaWRwIiwiZXhwIjo0MTAyNDQ0ODAwfQ."
    "")  # replaced below with a freshly-minted token if PyJWT is available

# Mint a correct token for the benchmark server's dev secret (keeps this file standalone).
try:
    import jwt, time
    TOKEN = jwt.encode({"sub": "agent-1", "sid": "agent", "scope": "",
                        "aud": "mcp-gateway", "iss": "mcp-gateway-idp", "exp": 4102444800},
                       "benchmark-dev-secret-key-0123456789abcdef", algorithm="HS256")
except Exception:
    pass

app = FastAPI(title="Gullible Agent (hijack test harness)")
_client = httpx.Client(timeout=10.0)

# --- naive intent extraction: obey any imperative found in the (poisoned) text ---
def decide_tool(text: str):
    t = text
    # shell / command intent
    if re.search(r"(?i)\b(run|exec|execute|bash|sh|shell|system)\b", t) or \
       re.search(r"(?i)(rm\s+-rf|\$\(|`|\|\s*nc|&&|;\s*\w|whoami|reboot|/etc/(passwd|shadow))", t):
        return "execute_bash", {"cmd": t}
    # url / ssrf intent
    m = re.search(r"https?://\S+", t)
    if m or re.search(r"(?i)\b(fetch|curl|wget|http|url)\b", t):
        return "fetch_url", {"url": m.group(0) if m else t}
    # sql intent
    if re.search(r"(?i)(union\s+select|drop\s+table|'\s*or\s*'?\d|--)", t):
        return "db_read", {"q": t}
    # file read intent
    if re.search(r"(?i)\b(read|open|cat|file)\b", t) or re.search(r"(\.\./|/etc/)", t):
        return "read_file", {"path": t}
    return None, None


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    text = body.get("input") or body.get("prompt") or body.get("messages", "")
    if isinstance(text, list):
        text = " ".join(str(m.get("content", m)) for m in text)
    text = str(text)

    tool, args = decide_tool(text)
    if not tool:
        return JSONResponse({"output": "No action taken (benign).", "executed": False,
                             "blocked_by_gateway": False, "tool": None})

    rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tool, "arguments": args}}
    try:
        r = _client.post(GATEWAY, json=rpc, headers={"Authorization": f"Bearer {TOKEN}"})
        j = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    except Exception as e:
        return JSONResponse({"output": f"gateway error: {e}", "executed": False,
                             "blocked_by_gateway": True, "tool": tool})

    if r.status_code in (400, 401, 413) or (isinstance(j, dict) and "error" in j):
        reason = (j.get("error", {}) or {}).get("message", f"HTTP {r.status_code}")
        return JSONResponse({"output": f"BLOCKED_BY_GATEWAY: {reason}", "executed": False,
                             "blocked_by_gateway": True, "tool": tool})
    # If we get here the gateway ALLOWED the (hijacked) action — an attack success.
    return JSONResponse({"output": f"EXECUTED: {tool} -> {json.dumps(j.get('result', j))[:200]}",
                         "executed": True, "blocked_by_gateway": False, "tool": tool})
