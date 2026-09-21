"""
RBAC control plane (AG-11).

V5 problems this fixes:
  * Admin authority was `agent_id == "admin_agent"` (a guessable username). Admin
    is now a JWT scope proven by the IdP (see auth.require_admin) and lives
    nowhere in this file.
  * is_authorized() opened a fresh AsyncSession and hit SQLite on EVERY tool call,
    and once PER TOOL during tools/list (N round-trips). -> A single cached fetch
    of an agent's allowed-tool set, reused for the whole tools/list filter.
  * Still fail-closed: unknown agent -> no tools.

The role store is injected via an async loader so the engine is backend-agnostic
(SQLite today, Postgres for a horizontally-scalable fleet tomorrow) and testable
without a database.
"""
from __future__ import annotations

import time
import logging
from typing import Awaitable, Callable, Optional, Set

logger = logging.getLogger("gateway.rbac")

RoleLoader = Callable[[str, str], Awaitable[Optional[list]]]


class RbacEngine:
    def __init__(self, loader: RoleLoader, cache_ttl: float = 30.0):
        self._loader = loader
        self._ttl = cache_ttl
        self._cache: dict[tuple[str, str], tuple[float, Set[str]]] = {}

    async def allowed_tools(self, agent_id: str, *, tenant_id: str = "default") -> Set[str]:
        key = (tenant_id, agent_id)
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit and now - hit[0] < self._ttl:
            return hit[1]
        raw = await self._loader(tenant_id, agent_id)
        allowed: Set[str] = set(raw) if raw else set()   # fail closed on missing role
        self._cache[key] = (now, allowed)
        return allowed

    async def is_authorized(self, agent_id: str, tool_name: str, *, tenant_id: str = "default") -> bool:
        allowed = await self.allowed_tools(agent_id, tenant_id=tenant_id)
        return "*" in allowed or tool_name in allowed

    def invalidate(self, agent_id: Optional[str] = None, *, tenant_id: str = "default") -> None:
        """Invalidate this process only; fleet-wide revocation is not implemented."""
        if agent_id is None:
            self._cache.clear()
        else:
            self._cache.pop((tenant_id, agent_id), None)
