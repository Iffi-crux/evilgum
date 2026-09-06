"""
Information-Flow Control engine (AG-05 + AG-05 deep fix / R9).

Two modes, selected by cfg.taint_mode:

  "coarse" (default): call-graph IFC. A session that touched a SOURCE is tainted;
     a tainted session may not call a SINK. Capability-based (net_egress/shell/
     fs_write/state_write = sink), unclassified tools default-deny, fetch_url is an
     egress sink, taint scoped to the conversation session with a TTL and untaint.
     This is the tested C+H-tier fix.

  "value" (R9, the market differentiator): VALUE-LEVEL IFC. We fingerprint the data
     a source tool actually RETURNS, and block a sink only when its arguments carry
     one of those tainted values. This is precise — it blocks real exfiltration
     (secret read from read_email appears in an http_post body) while allowing a
     tainted session to make unrelated sink calls, cutting the coarse mode's false
     positives. No competitor documents this.

Known limitation (documented, tracked): value mode matches tokens that survive
copy/substring; data that is re-encoded (e.g. base64) between source and sink is
not yet matched — that is the labelled-dataflow follow-up. The coarse gate remains
available as defense-in-depth for known-egress sinks.
"""
from __future__ import annotations

import os
import re
import hashlib
import logging
from enum import Enum
from typing import Any, Iterable, Set

import redis.asyncio as redis

from interceptor.config import PolicyConfig

logger = logging.getLogger("gateway.taint")

_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-@./+=]{4,}")


class TaintLevel(str, Enum):
    CLEAN = "CLEAN"
    TAINTED = "TAINTED"


class TaintEngine:
    def __init__(self, cfg: PolicyConfig, redis_client: "redis.Redis | None" = None):
        self.cfg = cfg
        self.ttl = cfg.taint_ttl_seconds
        if redis_client is not None:
            self.redis = redis_client
        else:
            url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
            self.redis = redis.from_url(url, decode_responses=True)

    # ---- locking + coarse state ----
    def get_lock(self, session_id: str):
        return self.redis.lock(f"lock:taint:{session_id}", timeout=5)

    async def get_level(self, session_id: str) -> TaintLevel:
        v = await self.redis.get(f"taint:{session_id}")
        return TaintLevel.TAINTED if v == TaintLevel.TAINTED.value else TaintLevel.CLEAN

    async def mark_tainted(self, session_id: str) -> None:
        await self.redis.set(f"taint:{session_id}", TaintLevel.TAINTED.value, ex=self.ttl)

    async def untaint(self, session_id: str) -> None:
        await self.redis.delete(f"taint:{session_id}", f"tvals:{session_id}")

    # ---- value-level fingerprints (R9) ----
    def _fingerprints(self, value: Any) -> Set[str]:
        text = value if isinstance(value, str) else _dumps(value)
        out: Set[str] = set()
        for tok in _TOKEN_RE.findall(text):
            if len(tok) >= self.cfg.taint_min_token_len:
                out.add(hashlib.sha256(tok.encode("utf-8")).hexdigest()[:16])
                if len(out) >= self.cfg.taint_max_tokens:
                    break
        return out

    async def capture_source_output(self, session_id: str, result: Any) -> int:
        """Fingerprint values a source tool returned so a later sink can be checked
        against them. Bounded by taint_max_tokens. Returns count captured."""
        fps = self._fingerprints(result)
        if not fps:
            return 0
        key = f"tvals:{session_id}"
        await self.redis.sadd(key, *fps)
        await self.redis.expire(key, self.ttl)
        return len(fps)

    async def _args_carry_tainted(self, session_id: str, arguments: Any) -> bool:
        arg_fps = self._fingerprints(arguments)
        if not arg_fps:
            return False
        # SMISMEMBER-style check; fall back to intersection for portability.
        stored = await self.redis.smembers(f"tvals:{session_id}")
        return bool(arg_fps & set(stored))

    # ---- decision ----
    async def evaluate_tool_call(self, session_id: str, tool_name: str, arguments: Any = None) -> bool:
        """Return True if permitted. MUST run inside get_lock(session_id)."""
        level = await self.get_level(session_id)
        is_sink = self.cfg.is_sink(tool_name)
        is_source = self.cfg.is_source(tool_name)

        if is_sink:
            if self.cfg.taint_mode == "value":
                # Precise: block only when the sink actually carries tainted data.
                if await self._args_carry_tainted(session_id, arguments):
                    logger.warning("IFC(value) block: tainted data -> sink '%s' (%s)", tool_name, session_id)
                    return False
            else:
                if level == TaintLevel.TAINTED:
                    logger.warning("IFC(coarse) block: tainted session %s -> sink '%s'", session_id, tool_name)
                    return False

        if is_source:
            await self.mark_tainted(session_id)

        return True

    async def close(self) -> None:
        try:
            await self.redis.aclose()
        except Exception:
            pass


def _dumps(v: Any) -> str:
    import json
    try:
        return json.dumps(v)
    except (TypeError, ValueError):
        return str(v)
