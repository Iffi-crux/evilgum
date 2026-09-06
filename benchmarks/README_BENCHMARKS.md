# External Benchmark Kit — run it in WSL

Point real security tools at the running gateway and get results you can paste back.
Everything here targets the gateway's `/rpc` endpoint. **Run the commands in order.**

> The gateway's own path in WSL is your Windows folder under `/mnt/c/...`. Set it once:
> ```bash
> cd "/mnt/c/Users/Afaq Amjad/Desktop/AI projects Pending/The MCP Rug Pull Interceptor & Taint Gateway"
> ```

---

## Step 1 — install Python deps (once)
```bash
pip3 install fastapi uvicorn "PyJWT[crypto]" redis fakeredis lupa pyyaml httpx starlette \
             pytest pytest-asyncio cryptography coverage prometheus-fastapi-instrumentator \
             sqlalchemy aiosqlite --break-system-packages
```

## Step 2 — start the gateway (leave this terminal running)
```bash
python3 -m uvicorn bench_server:app --host 127.0.0.1 --port 8080
```
You should see `Uvicorn running on http://127.0.0.1:8080`. **Open a SECOND WSL terminal** for the rest
(and `cd` to the same folder in it).

---

## Step 3 — instant attack replay  ⭐ (no extra installs, ~45 payloads)
```bash
bash benchmarks/attack_replay.sh
```
Prints `BLOCKED`/`ALLOWED` per attack and a final block-rate. **Paste me this whole output.**

## Step 4 — full in-house scanner (block-rate + fuzz + load + OWASP compliance)
```bash
python3 bench.py && cat bench_results.json
```
**Paste me the summary lines** (SECURITY / FUZZ / LOAD / COMPLIANCE).

## Step 5 — code coverage
```bash
python3 -m coverage run --branch -m pytest -q && python3 -m coverage report --include="interceptor/*,mesh/*"
```

---

## Step 6 — promptfoo (external OWASP tool, needs Node.js)  ⭐
```bash
cd benchmarks
npx promptfoo@latest eval -c promptfooconfig.yaml
npx promptfoo@latest view      # opens a browser report
cd ..
```
Each row should show **PASS** (payload BLOCKED). **Paste me the pass/fail summary.**

## Step 7 — nuclei (HTTP scanner)
```bash
# install once: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest   (or: sudo apt install nuclei)
nuclei -u http://127.0.0.1:8080 -t benchmarks/mcp-injection.yaml        # confirms our block fires
nuclei -u http://127.0.0.1:8080/rpc -H "Authorization: Bearer $(cat benchmarks/TOKEN.txt)"
```
On the second command, **0 findings is the GOOD result** — it means nuclei's CVE/misconfig templates found nothing.

## Step 8 — nmap (surface check)
```bash
nmap -sV -p 8080 127.0.0.1
```
Should show only port 8080 open running an HTTP service. **Paste the output.**

## Step 9 — OWASP ZAP API scan (optional, needs Docker)
```bash
docker run -t --network=host ghcr.io/zaproxy/zaproxy zap-api-scan.py \
   -t http://127.0.0.1:8080/rpc -f openapi 2>/dev/null || \
docker run -t --network=host ghcr.io/zaproxy/zaproxy zap-baseline.py -t http://127.0.0.1:8080
```

---

## Note on garak / PyRIT
These are **LLM red-teamers** — they send prompts to a chatbot and judge the *reply* for jailbreaks.
Our gateway is a JSON-RPC firewall with no LLM behind it, so they have nothing to grade. Skip them
for benchmarking the **gateway**. If you later put a real agent (with an OpenAI/Anthropic key) *behind*
the gateway, garak/PyRIT become useful for testing that whole agent — tell me and I'll wire it up.

## What to send back
The outputs of **Step 3, Step 4, Step 6, Step 7, Step 8**. I'll fold them into the benchmark
scorecard and we decide on deploy.
