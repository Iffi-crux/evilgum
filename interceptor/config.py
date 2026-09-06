"""
Single source of truth for gateway policy and configuration (AG-10).

The V5 codebase split policy across three places that disagreed:
  * hardcoded SOURCES/TRANSFORMS/SINKS sets in proxy.py
  * config.yaml (read only by the Rust build)
  * rbac.json (read only by the Rust build)

That "split brain" meant the deployed Python engine and the Rust engine
enforced *different* security policies. This module makes ONE typed policy
object the authority for the whole Python gateway, loaded from config.yaml
plus environment overrides. Nothing hardcodes a tool list anymore.
"""
from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Set, Optional, Any

import yaml

logger = logging.getLogger("gateway.config")


class Capability(str, Enum):
    """
    A tool is classified by what it can DO, not by a hand-maintained name list.
    A single tool may hold several capabilities (fetch_url both READS external
    data and can EXFILTRATE via its URL, so it is SOURCE *and* NET_EGRESS).
    """
    SOURCE = "source"          # ingests sensitive / attacker-influenced data
    TRANSFORM = "transform"    # pure, no side effects
    NET_EGRESS = "net_egress"  # can send data off-box (http, fetch, webhook)
    SHELL = "shell"            # can execute commands
    FS_WRITE = "fs_write"      # can write the filesystem
    STATE_WRITE = "state_write"  # can mutate durable state (db_write, messaging)


# Any of these capabilities makes a tool a SINK for information-flow purposes:
# data reaching such a tool has left the trust boundary.
SINK_CAPABILITIES: Set[Capability] = {
    Capability.NET_EGRESS,
    Capability.SHELL,
    Capability.FS_WRITE,
    Capability.STATE_WRITE,
}

# Default classification for tools this gateway knows about. Operators extend
# this via config.yaml -> tools.capabilities. Crucially, fetch_url is tagged
# NET_EGRESS (it was a "source" in V5, which made it a free exfil channel).
DEFAULT_CAPABILITIES: Dict[str, Set[Capability]] = {
    "read_file":          {Capability.SOURCE},
    "read_email":         {Capability.SOURCE},
    "db_read":            {Capability.SOURCE},
    "fetch_url":          {Capability.SOURCE, Capability.NET_EGRESS},
    "calculate_math":     {Capability.TRANSFORM},
    "format_json":        {Capability.TRANSFORM},
    "regex_match":        {Capability.TRANSFORM},
    "execute_bash":       {Capability.SHELL, Capability.NET_EGRESS},
    "http_post":          {Capability.NET_EGRESS},
    "send_slack_message": {Capability.NET_EGRESS, Capability.STATE_WRITE},
    "db_write":           {Capability.STATE_WRITE},
}


@dataclass
class PolicyConfig:
    # --- transport / identity ---
    env: str = "prod"
    kms_provider: str = "local"
    jwt_alg: str = "RS256"
    jwt_secret: Optional[str] = None          # HS* only, dev only
    jwt_public_key: Optional[str] = None       # RS*/ES* PEM
    jwt_jwks_url: Optional[str] = None          # enterprise SSO: IdP .well-known/jwks.json
    jwt_jwks_ttl: float = 600.0                 # JWKS cache TTL (seconds)
    jwt_audience: str = "mcp-gateway"
    jwt_issuer: str = "mcp-gateway-idp"
    admin_scope: str = "mcp.admin"

    # --- upstream ---
    upstream_url: str = "https://mock-mcp-backend:9090/rpc"
    upstream_tls_verify: bool = True
    upstream_ca_bundle: Optional[str] = None   # path to CA bundle for pinning
    client_cert: Optional[str] = None
    client_key: Optional[str] = None

    # --- limits ---
    max_body_bytes: int = 1_048_576            # 1 MB, enforced on bytes READ
    waf_inspect_bytes: int = 10_000
    reject_batch_on_any_denial: bool = True

    # --- taint ---
    taint_ttl_seconds: int = 3600              # 1h, not the V5 24h
    default_deny_unclassified_sinks: bool = True
    taint_mode: str = "coarse"                 # "coarse" (call-graph) or "value" (value-level IFC, AG-05 deep)
    taint_min_token_len: int = 6               # shortest source token we fingerprint
    taint_max_tokens: int = 512                # cap fingerprints per session (memory bound)

    # --- DLP (AG-14) ---
    dlp_egress_enabled: bool = True
    dlp_max_bytes: int = 20_000                # skip heavy NER above this response size

    # --- protocol (AG-19) ---
    method_allowlist_enforce: bool = True

    # --- enforcement mode (OBS/ROLLOUT) ---
    # "enforce": block on any denial (default). "shadow": compute every decision
    # and record what it WOULD block, but let traffic through (safe rollout /
    # tuning). "off": no security checks (transparent passthrough — use only to
    # isolate the gateway during an incident).
    enforcement_mode: str = "enforce"
    metrics_enabled: bool = True               # expose Prometheus /metrics

    # --- schema lock ---
    schema_lock_enforce: bool = True
    schema_lock_learn: bool = False            # auto-pin first-seen when True

    # --- macaroons ---
    macaroon_required: bool = False            # if True, missing macaroon is a denial

    # --- classification ---
    capabilities: Dict[str, Set[Capability]] = field(
        default_factory=lambda: {k: set(v) for k, v in DEFAULT_CAPABILITIES.items()})

    def classify(self, tool_name: str) -> Set[Capability]:
        """Capabilities for a tool. Unknown tools return an empty set; callers
        apply default-deny for sinks so an unenumerated tool is never a free
        egress channel (AG-05)."""
        return self.capabilities.get(tool_name, set())

    def is_sink(self, tool_name: str) -> bool:
        caps = self.classify(tool_name)
        if caps & SINK_CAPABILITIES:
            return True
        # Unknown tool + default-deny => treat as a sink (fail closed).
        if not caps and self.default_deny_unclassified_sinks:
            return True
        return False

    def is_source(self, tool_name: str) -> bool:
        return Capability.SOURCE in self.classify(tool_name)


def _bool_env(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def load_policy(config_path: str = "config.yaml") -> PolicyConfig:
    raw: Dict[str, Any] = {}
    try:
        with open(config_path, "r") as f:
            raw = yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("config.yaml not found; using built-in defaults + env")

    cfg = PolicyConfig()

    # Start from defaults, then layer config.yaml capability overrides.
    caps: Dict[str, Set[Capability]] = {k: set(v) for k, v in DEFAULT_CAPABILITIES.items()}
    tools = raw.get("tools", {}) or {}
    for name in tools.get("sources", []) or []:
        caps.setdefault(name, set()).add(Capability.SOURCE)
    for name in tools.get("transforms", []) or []:
        caps.setdefault(name, set()).add(Capability.TRANSFORM)
    for name in tools.get("sinks", []) or []:
        # A bare "sink" in legacy config maps to NET_EGRESS unless capabilities say more.
        caps.setdefault(name, set()).add(Capability.NET_EGRESS)
    for name, cap_list in (tools.get("capabilities", {}) or {}).items():
        caps.setdefault(name, set()).update(Capability(c) for c in cap_list)
    cfg.capabilities = caps

    up = raw.get("upstream_mcp", {}) or {}
    cfg.upstream_url = os.environ.get("UPSTREAM_MCP_URL", up.get("url", cfg.upstream_url))

    sec = raw.get("security", {}) or {}
    cfg.schema_lock_enforce = _bool_env("SCHEMA_LOCK_ENFORCE", sec.get("enforce_schema_lock", True))
    cfg.schema_lock_learn = _bool_env("SCHEMA_LOCK_LEARN", False)

    # Identity (env is authoritative; secrets never come from the repo).
    cfg.env = os.environ.get("GATEWAY_ENV", "prod")
    cfg.kms_provider = os.environ.get("GATEWAY_KMS_PROVIDER", "local")
    cfg.jwt_alg = os.environ.get("GATEWAY_JWT_ALG", "RS256")
    cfg.jwt_secret = os.environ.get("GATEWAY_JWT_SECRET")
    cfg.jwt_public_key = os.environ.get("GATEWAY_JWT_PUBLIC_KEY")
    cfg.jwt_jwks_url = os.environ.get("GATEWAY_JWT_JWKS_URL")
    cfg.jwt_jwks_ttl = float(os.environ.get("GATEWAY_JWT_JWKS_TTL", cfg.jwt_jwks_ttl))
    cfg.jwt_audience = os.environ.get("GATEWAY_JWT_AUDIENCE", cfg.jwt_audience)
    cfg.jwt_issuer = os.environ.get("GATEWAY_JWT_ISSUER", cfg.jwt_issuer)
    cfg.admin_scope = os.environ.get("GATEWAY_ADMIN_SCOPE", cfg.admin_scope)

    # Transport
    cfg.upstream_tls_verify = _bool_env("UPSTREAM_TLS_VERIFY", True)
    cfg.upstream_ca_bundle = os.environ.get("UPSTREAM_CA_BUNDLE")
    cfg.client_cert = os.environ.get("CLIENT_CERT")
    cfg.client_key = os.environ.get("CLIENT_KEY")

    cfg.macaroon_required = _bool_env("MACAROON_REQUIRED", False)
    cfg.taint_ttl_seconds = int(os.environ.get("TAINT_TTL_SECONDS", cfg.taint_ttl_seconds))
    cfg.taint_mode = os.environ.get("TAINT_MODE", cfg.taint_mode)
    cfg.dlp_egress_enabled = _bool_env("DLP_EGRESS_ENABLED", cfg.dlp_egress_enabled)
    cfg.method_allowlist_enforce = _bool_env("METHOD_ALLOWLIST_ENFORCE", cfg.method_allowlist_enforce)
    cfg.enforcement_mode = os.environ.get("GATEWAY_ENFORCEMENT_MODE", cfg.enforcement_mode).lower()
    cfg.metrics_enabled = _bool_env("GATEWAY_METRICS_ENABLED", cfg.metrics_enabled)

    return cfg
