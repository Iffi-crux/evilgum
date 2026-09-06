> Paste everything below into another AI as a single prompt. It rebuilds EvilGum — the product and its website — from scratch.

---

# Build EvilGum: an L7 security gateway for MCP (Model Context Protocol), plus its marketing site

You are building **EvilGum**, an open-source security firewall that sits **between an AI agent and its MCP tool servers**. The agent's MCP client points at EvilGum instead of at the tool server; EvilGum inspects every JSON-RPC request and response on the wire and blocks attacks before they reach the tools. It is open source (Apache-2.0) at **https://github.com/Iffi-crux/evilgum**; the official site lives at **evilgum.faseel.app**. Build two things: (A) the gateway, (B) the marketing website.

## A. The gateway

**Positioning.** An AI agent with tools is a trusted user with no judgment: a poisoned document, a swapped tool description, or a chained request can turn "summarize my inbox" into "email my inbox to an attacker." The model won't stop it — something on the wire has to. EvilGum is that layer. Fail-closed: an unknown or un-mediatable call is a blocked call.

**Stack.** Python 3.10+, FastAPI/Starlette, Uvicorn, httpx (upstream over verified mTLS), redis.asyncio (shared state), PyJWT[crypto], SQLAlchemy (roles), Presidio (optional DLP). Build it as a `create_app(cfg, deps)` factory with a `Deps` dataclass so every dependency (Redis, upstream, RBAC store, PII analyzer, audit log, metrics) can be injected with fakes in tests. Single POST endpoint `/rpc` proxies JSON-RPC; also `/healthz`, `/readyz`, `/metrics`.

**The eight controls** (each a separate module; run them as a pipeline per request, batch-aware — every element of a JSON-RPC batch runs the full pipeline and any denial fails the whole request closed):
1. **Identity** — verify a JWT on every call: asymmetric RS256/ES256 (public key or an IdP JWKS URL with key rotation), require `exp`/`aud`/`iss`/`sub`, derive authority from `scope`/`roles` claims. Admin is the `mcp.admin` scope, never a username. Refuse to boot on a missing/weak/placeholder secret. Extract a `tenant` claim (default `"default"`) and scope all shared state by `tenant:session`.
2. **RBAC** — each agent is allowed only the tools its role lists; everything else denied. Fail closed if the role store is unreachable. Filter `tools/list` responses to the caller's allowed set.
3. **Taint / information-flow control** — track tainted data across calls in a session; once a "source" tool (reads secrets/email/files) has run, block "sink" tools (shell, http_post, send_email) for that session. Two modes: coarse (call-graph) and value-level (fingerprint returned values so re-encoded exfil can be caught). State keyed per `tenant:session` in Redis, under a per-session lock.
4. **Rug-pull / schema-lock** — hash each tool's declared schema+description; block silent changes (a tool that was safe yesterday shipping an exfiltration primitive today). Detect description-poisoning ("ignore all rules…").
5. **Semantic WAF + DLP** — detect prompt-injection / shell / SQLi / SSRF payloads on ingress (decode-not-mutate: base64, url, hex before matching); redact PII/secrets on egress rather than dropping. Crash-safe.
6. **Macaroons** — attenuable HMAC-chained capability tokens; verify the signature before trusting caveats; enforce privilege-only-narrows and resource-scope-contains. Support root-key rotation (sign with primary, verify against previous keys).
7. **Tamper-evident audit log** — append every decision as hash-chained JSONL: `hash_n = SHA256(hash_{n-1} || seq || ts || canonical(event))`. A `verify(path)` recomputes the chain and reports the first break. Event = `{outcome, tenant, agent, session, tool, code, detail}`. Optional forward hook to a SIEM.
8. **Fail-closed everywhere** — unknown method (allowlist), parse error, downed dependency: all deny, never leak, never 500 (defensive catch-all returns a JSON-RPC fault).

**Enforcement modes** (`GATEWAY_ENFORCEMENT_MODE`): `enforce` (block on denial, default), `shadow` (run every control, record `would_deny_*` in the audit log + metrics, but forward the call — for safe rollout/tuning), `off` (transparent passthrough, incident escape hatch).

**Observability.** A dependency-free Prometheus collector at `/metrics`: `evilgum_decisions_total{outcome}`, `evilgum_allowed_total`/`blocked_total`/`would_block_total`, a request-latency histogram, `evilgum_up`. Keep cardinality low (label by outcome only; per-tenant lives in the audit log). `/healthz` = liveness (touches nothing); `/readyz` = Redis reachable (so a load balancer ejects a bad replica).

**High availability.** Replicas are stateless (all shared state in Redis) → run N behind an nginx LB; ship a `docker-compose.ha.yml` (redis + scalable gateway + nginx round-robin with `/readyz` health checks). The audit log is the one per-replica stateful piece — forward it to a SIEM or use a shared volume.

**Secrets.** Load JWT keys, macaroon root, and other secrets through a pluggable provider (env / mounted-file `/run/secrets` / cloud KMS/Vault interface), never hardcoded; support `secret://name` references and key rotation. *(Roadmap when you build it.)*

**Enterprise layer** (separate package `enterprise/`, imports from the core, nothing in the core imports it): SSO via JWKS (Okta/Entra/Auth0/Keycloak); multi-tenant isolation; a compliance-report generator that turns the audit log into SOC 2 / ISO 27001 / OWASP evidence (Markdown + light-theme HTML); a light-themed admin dashboard (FastAPI, admin-scope gated) showing live enforcement stats and control coverage.

**Quality bar.** ~110+ pytest tests with fakeredis, ~86% coverage, 0 errors under a 3000-case fuzz, 100% block on an attack corpus (rug-pull/injection/exfil/DoS), and 0% agent-hijack success under NVIDIA garak. Map controls to OWASP MCP / API / Agentic Top 10.

**Repo layout:** `interceptor/` (auth, rbac, taint, schema_lock, rate_limiter, egress_guard, semantic_waf, sidecar/macaroons, audit, metrics, proxy, app, config), `tests/`, `benchmarks/`, `docker-compose*.yml`, `Dockerfile`, `README.md`, `LICENSE` (Apache-2.0), `site/` (the website below).

## B. The marketing website

A single-page site, **committed to the repo at `site/index.html`**, hosted at **evilgum.faseel.app** (GitHub Pages + custom domain, or any static host). It MUST use EvilGum's official brand and MUST link to the open-source repo so visitors can reach the code.

**This is the official color format — match it exactly (light theme, pink accent; never dark):**
```
--bg:#fdf6fa;  --surface:#ffffff;  --surface-2:#fff2f8;
--ink:#2a1620; --muted:#8c7681;  --line:#f2dbe8;
--pink:#ff2d84 (accent);  --pink-deep:#d61a6b (text on white);  --pink-ink:#b3125a;
--pink-soft:#ffe1ef;  --ok:#12885b;
```
Fonts: **Bricolage Grotesque** (display/headings), **Hanken Grotesque** (body), **JetBrains Mono** (labels/code). Headlines and accents in pink; body text dark plum for readability; light ground throughout.

**Logo:** use the EvilGum logo — a neon cyber-girl blowing a pink bubblegum bubble over the "EvilGum" wordmark — as a **transparent PNG with the black background removed** (knock black out to transparency so it sits on the light ground). Mark (face+bubble) in the nav beside the "EvilGum" wordmark; full logo in the hero.

**Sections:** sticky nav (logo + links + a **GitHub** link/button → https://github.com/Iffi-crux/evilgum + "Get access") → hero (headline "The firewall that sits between your AI and its tools", a small **open-source · Apache-2.0 · github.com/Iffi-crux/evilgum** line, and a live Agent→EvilGum→Tools flow diagram showing ALLOW + two BLOCK verdicts) → the problem (rug-pulls, prompt injection, exfil) → how it works (intercept→inspect→decide→record) → the eight controls → benchmarks (0% garak ASR, 100% corpus, 0 fuzz errors, 110+ tests) → pricing (Community free/self-host with a "Get the repo" button to GitHub, Pro hosted, Enterprise custom) → enterprise features → contact (a form that composes a pre-filled email publicly, or POSTs to your backend when hosted) → footer with a GitHub link. Self-contained (inline CSS/JS, logo as data URI or in `site/assets/`), responsive, light-only.
