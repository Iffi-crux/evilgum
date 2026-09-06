# Contributing to EvilGum

Thanks for helping make MCP safer.

## Dev setup
```bash
pip install -r requirements.txt
python -m pytest -q          # 81 tests must stay green
python bench.py              # security + fuzz + load
```

## Ground rules
- **Every change ships with a test.** Security fixes ship with a test that fails before the fix and passes after.
- **Fail closed.** When in doubt, deny. A control that fails open is a bug.
- **No secrets in the tree.** Keys, tokens, and certs come from the environment. CI rejects commits that add them.
- Keep the `python bench.py` block-rate at 100% and fuzz at 0 server errors.

## Workflow
1. Fork → branch → PR against `main`.
2. Describe the threat your change addresses (link the OWASP MCP/API/Agentic item if it maps to one).
3. Green CI (tests + coverage) is required to merge.

## Scope
This repo is the open-source **core**. Commercial features (dashboard, SSO, multi-tenant control plane, hosted service) live elsewhere; PRs that add those here will be redirected.
