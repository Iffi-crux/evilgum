# High availability, safe rollout & observability

EvilGum sits in the request path of every agent tool call, so it must not be a
single point of failure, must be turn-on-able without breaking traffic, and must
be observable. This is how.

## 1. Horizontal scaling — the replicas are stateless

A gateway replica keeps **no per-request state in memory**. Everything shared
lives in Redis:

- **taint / information-flow state** — keyed by `tenant:session` in Redis
- **rate-limit buckets** — a Redis token bucket, timestamped from Redis's own
  clock so replicas with skewed wall-clocks agree

So you run N replicas behind a load balancer and any replica serves any request:

```bash
docker compose -f docker-compose.ha.yml up -d --scale gateway=3
```

The one piece of state that is **not** shared is the **audit log**. Each replica
appends to its own hash-chained file. Two options:

1. **Ship it (recommended).** The `AuditLog` has a `forward` hook — send each
   record to your SIEM (Splunk/Elastic/OTel) and treat that as the system of
   record. Per-replica files become local buffers.
2. **Shared volume.** For a small deployment, point every replica at one volume
   (as the compose file does). Note the chain is *per-replica*; verify each
   replica's chain independently.

Redis itself should be HA in production (Sentinel or a managed Redis). If Redis
is down the gateway **fails closed** in `enforce` mode — a blocked call, never a
leaked one.

## 2. Readiness & liveness

| Endpoint | Purpose | Behaviour |
|---|---|---|
| `GET /healthz` | Liveness | 200 as long as the process serves. Touches nothing. Restart the container if it fails. |
| `GET /readyz` | Readiness | 200 only if Redis is reachable. **Pull the replica from the LB** when it returns 503 — it can't enforce correctly without shared state. |

nginx (`deploy/nginx-ha.conf`) round-robins the pool and ejects a replica after
2 failures. Kubernetes users: wire `/healthz` to `livenessProbe` and `/readyz`
to `readinessProbe`.

## 3. Safe rollout — shadow mode

Never turn a firewall to full-enforce on live traffic blind. `GATEWAY_ENFORCEMENT_MODE`:

- **`shadow`** — every control runs and records what it *would* block
  (`would_deny_rbac`, `would_deny_taint`, …) in the audit log and in
  `evilgum_would_block_total`, but the call is **forwarded**. Run here for a
  week, read the would-blocks, fix the false positives.
- **`enforce`** — the default. Denials actually block.
- **`off`** — transparent passthrough, no checks. An incident escape hatch to
  isolate the gateway; not a normal operating mode.

Recommended path: deploy in `shadow` → tune policy from the would-block report →
flip to `enforce`.

## 4. Metrics

`GET /metrics` exposes Prometheus text (scrape it **in-mesh only** — the LB
returns 404 for `/metrics` at the edge):

| Metric | Meaning |
|---|---|
| `evilgum_requests_total` | requests processed |
| `evilgum_decisions_total{outcome}` | decisions by outcome (`allow`, `deny_rbac`, `would_deny_taint`, …) |
| `evilgum_allowed_total` / `evilgum_blocked_total` / `evilgum_would_block_total` | rolled-up counters |
| `evilgum_request_latency_seconds` | latency histogram |
| `evilgum_up`, `evilgum_uptime_seconds` | liveness gauge |

Per-tenant and per-agent breakdowns are deliberately **not** Prometheus labels
(cardinality). They live in the audit log and the enterprise admin dashboard.

### Alerts worth setting

- `rate(evilgum_blocked_total[5m])` spiking → an agent under attack or a broken policy.
- `evilgum_would_block_total` rising in shadow → policy not ready to enforce yet.
- `up == 0` or `/readyz` failing → replica down; the LB should already have ejected it.
