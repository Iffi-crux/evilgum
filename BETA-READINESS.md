# EvilGum beta readiness — 2026-09-21

Status: Phase 1 is complete for the supported single-worker profile: 166 core tests pass, one optional value-mode test is an expected failure; enterprise passes 20 tests. Seven live container recovery check groups passed. Public beta release remains gated on Phase 2 packaging. See PHASE1-OPERATIONS.md and MCP-COMPATIBILITY.md.

## Canonical source and launch scope

Use this nested evilgum repository as the core release candidate. The surrounding project directory is an older copy, and evilgum-enterprise is a separate component. This does not certify every difference between copies as reconciled.

Initial deployment target: one customer, one gateway process, one configured upstream. Tenant-aware roles are defense in depth, not a claim that the enterprise dashboard or a shared hosted service is ready.

## Verified in this change

- tools/call requires a pinned definition that has matched an upstream tools/list response during this process lifetime.
- An observed mismatched definition durably quarantines that tool until explicit offline operator approval and rediscovery. A later matching listing does not clear quarantine.
- Every definition in a listing is checked, including entries after a denied definition.
- Only a response correlated with a tools/list request can verify definitions.
- Resource, prompt, completion, roots, and logging methods are outside this beta scope and rejected before forwarding, even in shadow/off mode or when the old method-allowlist flag is false.
- RBAC loads, caches and invalidation use tenant plus agent. Admin CRUD derives tenant from the verified JWT; there is no request parameter for choosing another tenant.
- Tenant admin isolation is tested using the actual router and an SQLite database.

Historical pre-Phase-1 verification: 119 passed, 1 expected failure with the review environment. The initial 18 regression cases failed before the fixes; all 21 added cases now pass. The separate enterprise suite passes 19 tests after correcting its outdated theme assertion. The expected failure covers a known value-tracking re-encoding bypass; this is not comprehensive exfiltration prevention.

## Operator changes

1. Back up the existing role database before upgrade. The new tenant_roles table intentionally starts empty. The legacy roles table is retained but ignored; grants are not silently copied across tenants.
2. Recreate reviewed grants through POST /admin/roles/{agent_id}, using a signed mcp.admin token with the intended tenant claim. Missing tenant claims use default. GET uses the same scope.
3. Custom role loaders now accept (tenant_id, agent_id). A one-argument loader will fail closed.
4. Review and install mcp-lock.json before startup; keep SCHEMA_LOCK_ENFORCE=true and SCHEMA_LOCK_LEARN=false for beta enforcement. The checked-in empty lockfile permits no tool calls.
5. Request tools/list before calling tools after every restart. A batch combining initial discovery with a call is denied before forwarding; discovery must finish first.
6. After drift, stop traffic, investigate, approve a changed pin only if justified, restart, then perform discovery again. Quarantine is durable; observed matching definitions are process-local. Use the offline release-quarantine command after review. Learning is development-only and does not persist approved pins.
7. Use one process: the deployment enforces a single-worker file lock, serializes taint decisions and disables role caching. Do not deploy the HA example as a supported beta topology.

## Limits of this patch

Pins compare declared metadata, not implementation behavior. An upstream can change behavior without changing its schema. Changes are detected on a subsequent tool listing, not by re-fetching metadata before every call. Background notifications and refresh guarantees remain unimplemented.

Shadow/off modes are diagnostic modes, not protection modes; call denials may pass through. Listing post-processing still applies RBAC/schema checks. Use enforce for the beta.

The /mcp endpoint now passes official Python SDK 1.26.0 tests for MCP 2025-11-25 stateless JSON HTTP, including initialization notifications and version headers. Stateful sessions and SSE are explicitly rejected. The legacy /rpc adapter is disabled by the production builder. See MCP-COMPATIBILITY.md; do not advertise universal or drop-in MCP compatibility.

## Remaining release gates (not complete)

- Completed for the scoped stateless JSON profile: official SDK tests for errors, initialization notification, headers, discovery and fresh connections. Additional host/client combinations remain unverified.
- Completed: writable storage, Redis outage/state loss, SIGKILL restart and offline backup/fresh-volume restore; see PHASE1-OPERATIONS.md.
- Lock dependencies and verify a clean installation, build artifact and CI run; review environment success is not installation certification.
- Completed: module/symbol inventory and canonical-source decision (not a formal equivalence proof). The separate enterprise unit suite passes, but real deployment and tenant isolation of its dashboard remain unverified.
- Completed for supported profile: fail-closed bounded DLP, durable coarse taint, collision-safe session scopes; optional value mode is disallowed in production. Sensitive pilot scope still requires deployment review.
- Publish an accurate quickstart and a recorded allow/block demonstration using the supported client.
- Only then release a limited beta and recruit five trials. Public hosting, package publication and outreach have not happened.
