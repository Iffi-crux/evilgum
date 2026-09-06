# Pushing the two repos to github.com/faseel

You now have two clean, ready-to-push folders inside this project:

```
evilgum/              →  github.com/Iffi-crux/evilgum            (PUBLIC, Apache-2.0)  ← the open-source core
evilgum-enterprise/   →  github.com/Iffi-crux/evilgum-enterprise (PRIVATE, proprietary) ← SSO, compliance, dashboard
```

Everything sensitive (real keys, `data/`, `.env`, the old `_v5_backup`, `archive/`,
`certs/`, the stray `MCP INTERCEPTOR/` folder) was **left out of both** — they were
never copied in, and `.gitignore` blocks them anyway.

> `gh` (the GitHub CLI) is not installed on this machine, so create each repo in the
> browser first (empty — no README/License/gitignore), then run the commands below.
> Use an HTTPS URL and a Personal Access Token when git asks for a password, or set up SSH.

## 1 · Public core → `evilgum`

Create an **empty public** repo at `https://github.com/new` named `evilgum`, then:

```bash
cd "evilgum"
git init -b main
git add .
git status            # eyeball: NO .key / .env / .db / _v5_backup / data/
git commit -m "EvilGum: open-source core — MCP security gateway (0% garak ASR, 100% corpus)"
git remote add origin https://github.com/Iffi-crux/evilgum.git
git push -u origin main
git tag v0.1.0 && git push --tags
```

## 2 · Private enterprise → `evilgum-enterprise`

Create an **empty PRIVATE** repo named `evilgum-enterprise`, then:

```bash
cd "evilgum-enterprise"
git init -b main
git add .
git status            # only enterprise/, tests/, pyproject.toml, README.md, LICENSE, .gitignore
git commit -m "EvilGum Enterprise: SSO (JWKS), compliance reporting, admin dashboard"
git remote add origin https://github.com/Iffi-crux/evilgum-enterprise.git
git push -u origin main
```

## 3 · Verify the split builds

```bash
# core, standalone
cd evilgum && python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]" && pytest -q          # core + tenancy tests

# enterprise, against the sibling core
cd ../evilgum-enterprise
pip install -e ../evilgum && pip install -e ".[dev]"
pytest -q                                     # SSO + compliance + dashboard tests
```

## What went where

| | `evilgum` (public) | `evilgum-enterprise` (private) |
|---|---|---|
| Engine (`interceptor/`, `mesh/`, `detector/`) | ✅ | — (installed as a dependency) |
| Core tests incl. multi-tenant isolation | ✅ | — |
| Benchmarks, Docker, configs, README | ✅ | — |
| `enterprise/` (SSO, compliance, dashboard) | — | ✅ |
| Enterprise tests + `pyproject.toml` | — | ✅ |
| License | Apache-2.0 | Proprietary |

> Multi-tenant lives as a *primitive* in the public core (`Principal.scope_id`,
> harmless and backward-compatible) while the tenant **control plane / dashboard**
> is the paid layer — the standard open-core boundary.
