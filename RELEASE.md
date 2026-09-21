# Release candidate 0.1.0rc1

Supported packaged runtime: Linux amd64, Python 3.11, Docker Engine and Compose v2-compatible CLI. Windows with Ubuntu WSL is a tested development route; native Windows/macOS Docker and ARM are not certified. The wheel declares Python 3.11–3.12; the locked release environment is Python 3.11/Linux.

## Build from the source archive

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r locks/build.lock
SOURCE_DATE_EPOCH=1789948800 python -m build --no-isolation
# For installed runtime dependencies (including DLP model):
python -m pip install --require-hashes -r locks/runtime-py311-linux.lock
python -m pip install --no-deps dist/evilgum-0.1.0rc1-py3-none-any.whl
python -m pip check
evilgum --version
evilgum init-config --directory ./deployment
```

The bootstrap copies packaged examples and empty pins and refuses overwrites. Review policy, approve pins and follow PHASE1-OPERATIONS.md before deployment. Installation alone does not configure a customer IdP or make an exposed service safe. Container builds install the exact wheel, not source folders.

```sh
docker build --platform linux/amd64 -t evilgum:0.1.0rc1 .
EVILGUM_TEST_IMAGE=evilgum:0.1.0rc1 python scripts/verify_phase1.py
```

The hash locks pin all resolved Python dependencies, including the spaCy model. The Docker base and Redis references are pinned by digest. The image digest is reported separately after publication; a digest identifies the artifact, not a security assessment. Rebuilding needs access to those locked package URLs. The license inventory covers Python dependencies; it does not replace a full operating-system SBOM/legal review.

## Tests and CI

Install locks/test-py311-linux.lock with --require-hashes, install the built wheel with --no-deps, then run tests from outside the source tree. The release workflow builds artifacts, verifies installation, runs regressions and the disposable container drill, and uploads evidence. A passing local run is not described as a hosted CI run.

## Upgrade and rollback

There is no previous public packaged release. Do not claim general version-to-version downgrade support. The recorded baseline rollback uses the local Phase 1 image against a restored snapshot; the candidate same-version restore is also checked.

1. Stop the sole gateway; save the previous exact image digest, configuration, pins and separately protected issuer/TLS secrets.
2. Back up state offline with interceptor.recovery backup. Verify and store the archive off-host. Legacy pre-Phase-1 installs lack this state format: preserve their original database separately, initialize a NEW deployment and re-grant reviewed tenant roles. Never silently import unscoped roles.
3. Restore the backup into a NEW volume, deploy the candidate against it, issue fresh eg_epoch sessions and perform discovery/allow/deny/audit checks before redirecting traffic. Keep the original volume stopped and untouched.
4. On failure, stop the candidate. Restore the pre-upgrade backup into another NEW volume using the compatible known-good image; issue the NEW recovery epoch, test controls, then redirect traffic. Do not attach an older image to state migrated by an unknown newer version. Expect loss of changes after the backup; reconcile actions manually.
5. Do not run old and new instances simultaneously against one volume. Retain the fallback image and snapshot until the acceptance window ends.

## Troubleshooting and uninstall

- 401 after restore: obtain a freshly signed JWT containing the new eg_epoch, correct issuer/audience, tenant and sid.
- No callable tools: review grants/pins and complete tools/list after startup.
- Quarantine: investigate and use explicit offline release-quarantine; restarting cannot clear it.
- Startup missing-state error: recover a complete verified backup; do not create empty files.
- Readiness failure: check Redis and writable UID 10001 data volume. DLP must load its packaged model.
- Image build missing wheel: build the wheel first, in the same source root.
- Demo issues: inspect the report/log paths printed by the drill. It removes only its uniquely named Docker resources and leaves synthetic fixtures locally.

For a dedicated deployment, stop with docker compose -f docker-compose.prod.yml down. This preserves named volumes. Export required backups before explicitly removing that deployment's named volumes; do not run global Docker prune commands. Remove only your own extracted quickstart and virtual environment when no longer needed.

## Acceptance still requiring people

An independent tester must follow the README and report installation/activation friction. We cannot count our synthetic runs as an outside tester or one of the first five users. A release candidate can be offered for this evaluation; it is not a declaration of general availability.
