#!/bin/bash
# Anti Gravity MCP Network Enforcer
# This script configures host-level iptables to prevent Server-Side Request Forgery (SSRF)
# by blocking direct egress from the MCP Server container and forcing traffic to the L7 Proxy.

set -e

PROXY_UID=$(id -u antigravity_proxy || echo 999)
PROXY_PORT=8080

echo "[*] Anti Gravity: Initializing Network Enforcement Boundary..."

# 1. Flush existing rules
iptables -F OUTPUT
iptables -t nat -F OUTPUT

# 2. Prevent SSRF to Cloud Metadata Endpoints
echo "[+] Blocking AWS/GCP Metadata endpoints (169.254.169.254)..."
iptables -A OUTPUT -d 169.254.169.254 -j DROP

# 3. Block direct RFC 1918 Access (Internal Networks) unless via Proxy
# We drop traffic to internal subnets for all users EXCEPT the proxy daemon.
echo "[+] Dropping direct RFC 1918 traffic (except for Proxy UID: $PROXY_UID)..."
iptables -A OUTPUT -d 10.0.0.0/8 -m owner ! --uid-owner $PROXY_UID -j REJECT
iptables -A OUTPUT -d 172.16.0.0/12 -m owner ! --uid-owner $PROXY_UID -j REJECT
iptables -A OUTPUT -d 192.168.0.0/16 -m owner ! --uid-owner $PROXY_UID -j REJECT

# 4. Optional: Force all port 80/443 traffic to pass through the local proxy
# iptables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -m owner ! --uid-owner $PROXY_UID -j REDIRECT --to-ports $PROXY_PORT

echo "[*] Network isolation rules applied."
