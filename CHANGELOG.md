# 0.1.0rc2 — Enterprise integration interfaces

- Production app factory accepts a verifier factory while retaining the same enforcement, durability and recovery lifecycle.
- Audit verification accepts an existing snapshot so management reports verify the exact bytes they summarize.
- Candidate packaging derives versioned artifact names from project metadata.
- Recovery acceptance supports an explicit previous-image upgrade check.

The supported single-worker, isolated stateless HTTP/JSON beta profile remains unchanged. Enterprise remains a separately licensed private add-on.

# Changelog

## 0.1.0rc1 — 2026-09-21

First packaged developer-beta candidate for an isolated single-worker MCP deployment.

- Scoped /mcp JSON transport and official Python SDK integration coverage.
- Approved schema discovery before calls and durable quarantine after observed drift.
- Tenant-scoped roles and collision-safe conversation identities.
- Durable coarse taint, strict DLP, and audit intent before forwarding.
- Non-root read-only container with writable state; corrected upstream mTLS context.
- Offline backup/restore, fresh recovery epoch credentials and missing-state refusal.
- Installed configuration bootstrap, hash-locked dependencies, wheel/source/image and disposable recovery quickstart.

Breaking deployment changes: production /rpc disabled; coarse/enforce/DLP required; single worker only; local SQLite paths fixed to the durable data directory; signed JWTs must contain deployment eg_epoch. Legacy role grants require reviewed tenant re-granting. Existing live deployments must use the migration procedure in RELEASE.md.

This candidate is not an enterprise release. Enterprise recovery-verifier compatibility changes remain in its separate repository.
