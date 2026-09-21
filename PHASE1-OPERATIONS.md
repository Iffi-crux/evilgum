# Phase 1 operations — supported beta profile

Verified 21 September 2026. Canonical source: the nested evilgum repository. Container runtime: Python 3.11; local review tests: Python 3.12. One isolated customer deployment, one gateway worker, one upstream, SQLite on a local durable volume. HA/shared SaaS and network-mounted SQLite are outside this profile.

## Configure and start

Build the candidate wheel first following RELEASE.md, then use docker-compose.prod.yml. Supply the JWT public key, issuer/audience, a strong MACAROON_ROOT_KEY, REDIS_PASSWORD, HTTPS upstream URL, and the upstream CA/client certificate/private key in the referenced secrets directory. Keep credentials outside source control. Review config.yaml and install approved mcp-lock.json pins before building. The empty example pins permit no tools. Production requires enforce mode, coarse taint, schema enforcement, no learning, and working Presidio DLP.

```sh
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml run --rm --no-deps mcp-firewall python -m interceptor.recovery init --data-dir /app/data
```

Configure your trusted issuer to include the returned epoch as the signed JWT claim eg_epoch. Issue short-lived tokens with the intended tenant, subject, scopes and a stable conversation sid. A new authorized sid represents a new conversation; do not let an untrusted client self-issue session identities. Never run init against existing state.

```sh
docker compose -f docker-compose.prod.yml up -d
```

Check /readyz, create reviewed tenant roles through the authenticated admin API, and complete tools/list before tools/call after each restart. Requests must use the supported /mcp profile in MCP-COMPATIBILITY.md; production /rpc is disabled. The host port binds to loopback: configure and validate your HTTPS ingress before remote use. The container drill verifies outbound mutual TLS, not a deployed public ingress or a real customer IdP.

The image runs as UID 10001 with a read-only root and writable named /app/data volume. Keep DATABASE_URL, AUDIT_LOG_PATH and EVILGUM_DATA_DIR at the supplied paths. One worker is enforced by an OS file lock. Do not scale replicas, use uvicorn workers, or start another gateway against a copied live database.

## Durable behavior and failure recovery

admin.db holds tenant roles; security.db holds taint/quarantine; audit.log.jsonl holds the audit chain; recovery.json contains the required epoch; initialized.json guards against missing initialized databases. Preserve the whole volume. Role caching is disabled in this deployment. Taint never automatically expires; Redis flush/restart cannot clear it. Source/sink decisions are serialized within the sole worker. A tainted conversation requires a new trusted session to begin again.

Redis outage denies requests. Missing initialized durable state refuses startup. DLP failure or oversized inspected bodies fail closed. A durable forward-intent audit entry is required before upstream execution; final outcome logging may fail after an upstream action has already occurred, so a forward-intent record is not proof of completion. Audit fsync and SQLite FULL synchronization improve durability but do not certify underlying hardware against power loss.

Schema quarantine survives restart. Investigate changes, review and install the intended pin, stop the gateway, then explicitly approve that exact pin:

```sh
docker compose -f docker-compose.prod.yml stop mcp-firewall
docker compose -f docker-compose.prod.yml run --rm --no-deps mcp-firewall python -m interceptor.recovery release-quarantine --data-dir /app/data --pins /app/mcp-lock.json --tool TOOL_NAME --approved-hash REVIEWED_64_CHARACTER_HASH
docker compose -f docker-compose.prod.yml up -d mcp-firewall
```

Complete discovery again before calling. A matching later listing alone cannot clear quarantine. Pins check metadata, not tool implementation; drift is detected when observed in a listing, not continuously.

## Offline backup and restore

Stop the gateway before backup. Use a unique backup filename. Archives contain role/audit/security data and configuration: treat them as sensitive operational data, never as public release assets. Keep secrets separately; ensure your policy file does not embed credentials.

```sh
docker compose -f docker-compose.prod.yml stop mcp-firewall
docker compose -f docker-compose.prod.yml run --rm --no-deps mcp-firewall python -m interceptor.recovery backup --data-dir /app/data --output /app/data/backup-001.zip --policy /app/config.yaml --pins /app/mcp-lock.json
docker compose -f docker-compose.prod.yml cp mcp-firewall:/app/data/backup-001.zip ./backup-001.zip
docker compose -f docker-compose.prod.yml up -d mcp-firewall
```

Store the archive off-host with appropriate access control. Its manifest detects corruption, not malicious replacement by someone able to rewrite both files and checksums. Audit chaining detects internal edits and sequence gaps; detecting suffix removal or full rewriting requires an independently trusted external checkpoint.

Restore into a NEW EMPTY volume owned by UID 10001, never over live state. With that volume mounted at /app/data and the archive mounted read-only at /backup/backup.zip, run the tested image command:

```sh
python -m interceptor.recovery restore --input /backup/backup.zip --destination /app/data
```

Use the restored config.yaml and mcp-lock.json as the deployment configuration. Point compose at the restored volume. Update the issuer with the returned NEW eg_epoch and issue fresh sessions; previous tokens must return 401. Reconnect, rediscover tools and verify role denial, taint denial, quarantine and audit integrity before reopening traffic. Restoring an older snapshot does not recover later events; select backup frequency for your acceptable data-loss window. The epoch prevents old sessions resuming silently against that older snapshot.

## Repeat the disposable drill

Build/tag the core image evilgum-phase1:local and make redis:7-alpine available. Run python scripts/verify_phase1.py from a development environment with cryptography and HTTP test dependencies. On Windows it uses Docker in Ubuntu WSL. It creates uniquely named test containers, volumes and synthetic TLS/JWT material; only its own Docker resources are removed. Local ignored .phase1-runtime fixtures retain synthetic keys and must never enter release bundles.

Verified: boot under read-only/non-root restrictions, upstream mTLS, actual DLP redaction, allow/deny, Redis outage and state loss, SIGKILL/restart, offline backup/fresh-volume restore, rejection of old tokens, audit-chain verification and refusal to start with missing security state. Physical host reboot/power failure was not tested. scripts/compare_sources.py inventories duplicate outer modules; no outer-only modules were found. The outer proxy audit helper is represented by the canonical record/alias implementation. Freeze the outer copy; do not release from it. This inventory is not a formal equivalence proof.

## Remaining release gates

Phase 2 still requires dependency locking, reproducible wheel/source/container artifacts, clean packaged installation, upgrade/rollback verification, external onboarding, and verified public downloads. Enterprise needs real IdP integration and dashboard/report isolation verification before an enterprise pilot. Value-tracking mode retains a known re-encoding limitation and is rejected by the production profile. No claim of universal exfiltration prevention is made.
