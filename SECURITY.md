# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.
Email **info@faseel.app** (or visit [faseel.app/evilgum](https://faseel.app/evilgum)) with details and steps to reproduce. We aim to acknowledge within 72 hours and to coordinate a fix and disclosure timeline with you.

## Security posture (honest)

EvilGum is a security control, so we hold ourselves to the standard we sell.

**Externally validated / measured on this codebase:**
- NVIDIA garak agent-hijack scan: **0% Attack Success Rate** (~15,000 attempts, 12/12 probes PASS).
- Attack corpus: **100% blocked** (56 payloads, OWASP-mapped).
- Robustness: **0 unhandled errors** across 3,000 fuzzed requests.
- **86%** line+branch coverage across **81** adversarial tests.

**Standards mapping:** OWASP MCP Top 10, OWASP API Security Top 10 (2023), OWASP Top 10 for Agentic Applications.

**Not yet done (do not deploy to regulated production without these):**
- Third-party penetration test (required for SOC 2 / enterprise).
- Multi-tenant isolation hardening.
- Published latency/throughput envelope on production infrastructure.

## Hard requirements before production

The gateway **refuses to start** on unsafe config, but you must supply:
- `GATEWAY_JWT_PUBLIC_KEY` from a real IdP (RS256/ES256) — never the dev HS256 secret.
- `MACAROON_ROOT_KEY` (≥32 bytes) and mTLS certs from a secret manager; `UPSTREAM_TLS_VERIFY=true`.
- `DATABASE_URL` pointing at Postgres (not SQLite) for RBAC + the audit log at scale.

## Reproducing our claims

```bash
python bench.py
python -m coverage run --branch -m pytest && python -m coverage report
garak -m rest -G benchmarks/garak_mcp_rest.json -p latentinjection,promptinject
```
