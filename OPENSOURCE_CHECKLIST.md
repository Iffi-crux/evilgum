# Open-sourcing checklist — what to push to github.com/faseel

> The `.gitignore` in this repo already excludes the private/secret stuff automatically.
> This is the human double-check before your first push.

## ✅ PUSH — the open-source core
```
interceptor/        # the engine: auth, rbac, taint, schema_lock, rate_limiter, egress_guard, admin, audit, proxy, app, config
mesh/               # semantic_waf.py, sidecar.py (macaroons)
detector/           # math_engine.py
tests/              # all 81 tests
benchmarks/         # attack_replay.sh, bench configs, garak/promptfoo, READMEs   (TOKEN.txt is git-ignored)
bench.py  bench_server.py  agent_harness.py  run_dev.py
config.yaml  requirements.txt  Dockerfile  Dockerfile.mock
docker-compose.yml  docker-compose.prod.yml
mock_mcp_server.py  demo_client.py  locustfile.py  rigorous_locust.py  apt_red_team_locust.py
rbac.json           # ship as an EXAMPLE (demo roles only)
README.md  LICENSE  SECURITY.md  CONTRIBUTING.md  REMEDIATION_V6.md  .gitignore
```

## ❌ DO NOT PUSH — delete or leave ignored
| Path | Why | Action |
|---|---|---|
| `certs/` , `*.key` , `*.pem` | real keys/certs | git-ignored; **rotate & delete the key** |
| `_to_delete/` | holds the exposed dev key | **delete the folder** |
| `_v5_backup/` | the OLD vulnerable code | **delete** — never ship the pre-fix version |
| `archive/rust-legacy/` | half-built, enforces a different policy | delete, or keep private |
| `MCP INTERCEPTOR/` | stray nested git repo | **delete** |
| `data/` , `*.db` , `*.jsonl` | runtime state + audit logs | git-ignored |
| `__pycache__/` , `.pytest_cache/` , `.coverage` | build junk | git-ignored |
| `.env` , `benchmarks/TOKEN.txt` | secrets/tokens | git-ignored |

## 🏢 BUILD LATER — the private "enterprise" repo (Iffi-crux/evilgum-enterprise)
None of this exists yet — it's your future paid layer, not files you hold back:
- Admin **dashboard UI** (web frontend)
- **SSO / Okta / Entra** connectors
- **Multi-tenant** isolation + control plane
- **Compliance report** generator (SOC 2 / ISO evidence)
- **Hosted SaaS** control plane + billing

> Decision to make now: **value-level taint** (`taint_mode=value`) IS built and IS your differentiator.
> Recommended: **open it** (adoption > protecting one feature; your moat becomes hosting + dashboard + support).
> If you'd rather gate it, move that branch of `interceptor/taint.py` into the private repo before first push.

## Commands (first push)
```bash
cd "The MCP Rug Pull Interceptor & Taint Gateway"

# 1) clean the junk that must not ship
rm -rf _v5_backup _to_delete "MCP INTERCEPTOR" archive certs data __pycache__ */__pycache__

# 2) start a fresh git history (the old nested .git is gone with the folder above)
git init -b main
git add .
git status            # <-- eyeball this: confirm NO .key/.env/.db/_v5_backup slipped in
git commit -m "EvilGum: open-source core — MCP security gateway (0% garak ASR, 100% corpus)"

# 3) create the repo on GitHub under your org, then:
git remote add origin https://github.com/Iffi-crux/evilgum.git
git push -u origin main

# 4) tag a release
git tag v0.1.0 && git push --tags
```

## Before you go public — 30-second sanity sweep
- [ ] `git grep -i "mock_secret_key\|BEGIN PRIVATE KEY\|password ="` returns nothing real
- [ ] `README.md` shows the diagram + benchmark badges
- [ ] `python -m pytest -q` is green on a fresh clone
- [ ] repo name is business-neutral (`evilgum`, not "Rug Pull Interceptor")
