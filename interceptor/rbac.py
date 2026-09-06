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

RoleLoader = Callable[[str], Awaitable[Optional[list]]]


class RbacEngine:
    def __init__(self, loader: RoleLoader, cache_ttl: float = 30.0):
        self._loader = loader
        self._ttl = cache_ttl
        self._cache: dict[str, tuple[float, Set[str]]] = {}

    async def allowed_tools(self, agent_id: str) -> Set[str]:
        now = time.monotonic()
        hit = self._cache.get(agent_id)
        if hit and now - hit[0] < self._ttl:
            return hit[1]
        raw = await self._loader(agent_id)
        allowed: Set[str] = set(raw) if raw else set()   # fail closed on missing role
        self._cache[agent_id] = (now, allowed)
        return allowed

    async def is_authorized(self, agent_id: str, tool_name: str) -> bool:
        allowed = await self.allowed_tools(agent_id)
        return "*" in allowed or tool_name in allowed

    def invalidate(self, agent_id: Optional[str] = None) -> None:
        """Call when a role changes via /admin so replicas don't serve stale grants."""
        if agent_id is None:
            self._cache.clear()
        else:
            self._cache.pop(agent_id, None)
