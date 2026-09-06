"""
Benchmark server — the real gateway on a real port for external scanners
(nuclei / ZAP / promptfoo / curl). Broad roles so attack payloads reach the WAF
+ taint layers instead of stopping at RBAC.

Run:  python -m uvicorn bench_server:app --host 127.0.0.1 --port 8080
Auth: every /rpc request needs  Authorization: Bearer <token from benchmarks/TOKEN.txt>
"""
from bench import build_app

app, _cfg = build_app()
