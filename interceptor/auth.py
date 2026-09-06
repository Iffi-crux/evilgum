"""
Identity layer (AG-01, AG-11-admin, AG-15, AG-16).

V5 verified every JWT against MOCK_SECRET_KEY = "mock_secret_key" hardcoded in
proxy.py, and decided admin by `agent_id == "admin_agent"`. Anyone with the repo
could forge an admin token. This module:

  * verifies against an asymmetric key (RS256/ES256) supplied by a real IdP,
    or an HS256 secret in dev ONLY — loaded from the environment, never code;
  * REFUSES TO START on a missing / weak / known-placeholder secret;
  * requires exp, aud and iss on every token (no eternal / cross-audience tokens);
  * requires a non-empty sub (no silent collapse to "unknown_agent");
  * derives authority from scopes/roles claims, so admin is a *capability*
    (`mcp.admin` scope) proven by the IdP, not a guessable username.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

import jwt  # PyJWT

from interceptor.config import PolicyConfig
from interceptor.kms import get_kms_client

logger = logging.getLogger("gateway.auth")

# Secrets we refuse to boot with, so a demo secret can never reach production.
_BANNED_SECRETS = {
    "mock_secret_key", "secret", "changeme", "password", "test", "dev",
    "anti_gravity_root_key", "",
}
_MIN_SECRET_LEN = 32


class AuthError(Exception):
    """Raised for any authentication failure -> HTTP 401."""


@dataclass
class Principal:
    agent_id: str                 # sub claim
    scopes: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    session_id: str = ""          # per-conversation taint scope (sid/jti), NOT the identity
    token_id: str = ""            # jti, for replay tracking
    tenant_id: str = "default"    # multi-tenant isolation (tenant/org/tid claim)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    @property
    def scope_id(self) -> str:
        """Tenant-scoped key for shared state (taint, rate-limit) so tenants never collide."""
        return f"{self.tenant_id}:{self.session_id}"


class JwtVerifier:
    def __init__(self, cfg: PolicyConfig):
        self.cfg = cfg
        self.alg = cfg.jwt_alg
        self._key = self._resolve_key(cfg)

    def _resolve_key(self, cfg: PolicyConfig) -> str:
        alg = cfg.jwt_alg.upper()
        kms = get_kms_client(cfg.kms_provider)
        
        if alg.startswith("HS"):
            if cfg.env == "prod":
                raise RuntimeError(
                    "Refusing to start: symmetric JWT (HS*) is not permitted in prod. "
                    "Set GATEWAY_JWT_ALG=RS256/ES256 with a real IdP public key."
                )
            
            # Fetch from KMS (fallback to env in dev)
            secret = kms.resolve_secret("GATEWAY_JWT_SECRET") if not cfg.jwt_secret else cfg.jwt_secret
            
            if not secret or secret.strip().lower() in _BANNED_SECRETS or len(secret) < _MIN_SECRET_LEN:
                raise RuntimeError(
                    "Refusing to start: GATEWAY_JWT_SECRET is missing, a known placeholder, "
                    f"or shorter than {_MIN_SECRET_LEN} chars. No secrets in source."
                )
            return secret
        # Asymmetric: public key (PEM) from env / IdP.
        pub_key = kms.resolve_public_key("GATEWAY_JWT_PUBLIC_KEY") if not cfg.jwt_public_key else cfg.jwt_public_key
        if not pub_key:
            raise RuntimeError(
                "Refusing to start: GATEWAY_JWT_PUBLIC_KEY (PEM) is required for asymmetric JWT."
            )
        return pub_key

    def verify(self, token: str) -> Principal:
        try:
            payload = jwt.decode(
                token,
                self._key,
                algorithms=[self.alg],
                audience=self.cfg.jwt_audience,
                issuer=self.cfg.jwt_issuer,
                options={
                    "require": ["exp", "aud", "iss", "sub"],
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_signature": True,
                },
            )
        except jwt.PyJWTError as e:
            # Do not leak which check failed.
            raise AuthError("invalid or expired token") from e

        sub = payload.get("sub")
        if not sub or not isinstance(sub, str):
            raise AuthError("token missing subject")

        scopes = _as_list(payload.get("scope") or payload.get("scp") or payload.get("scopes"))
        roles = _as_list(payload.get("roles"))
        # Taint scope: prefer an explicit session id claim, else the token id,
        # so taint is per-conversation and never sticks to the identity forever.
        session_id = payload.get("sid") or payload.get("jti") or f"{sub}:{payload.get('iat','')}"
        tenant = payload.get("tenant") or payload.get("org") or payload.get("tid") or "default"
        return Principal(
            agent_id=sub,
            scopes=scopes,
            roles=roles,
            session_id=str(session_id),
            token_id=str(payload.get("jti", "")),
            tenant_id=str(tenant),
        )


def _as_list(v) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [s for s in v.replace(",", " ").split() if s]
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return []


def require_admin(principal: Principal, cfg: PolicyConfig) -> None:
    """Admin is a proven scope, not a username (AG-11-admin)."""
    if not principal.has_scope(cfg.admin_scope):
        raise AuthError("admin scope required")
