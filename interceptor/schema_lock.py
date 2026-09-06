"""
Schema-lock / rug-pull detection (AG-07).

V5 problems this fixes:
  * The shipped lockfile was all "dummy_hash", which the code explicitly skipped,
    so the feature was OFF by default. -> No dummy skip; enforcement is the default.
  * Missing lockfile dropped into silent "learning mode" (enforce nothing). ->
    Learning is opt-in (SCHEMA_LOCK_LEARN); otherwise an unpinned tool is flagged.
  * It hashed the whole tool object, so a benign description edit was a false
    "RUG PULL" while it also missed description POISONING. -> We hash the
    security-relevant surface (name + inputSchema + description) deliberately:
    a changed description IS an attack we want to catch; re-pinning is an explicit
    operator action, which is the point of a lock.

Returns a verdict per tool so the caller can block on drift and (optionally)
auto-pin first-seen tools in learning mode.
"""
from __future__ import annotations

import json
import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger("gateway.schema_lock")


def compute_hash(tool: Dict[str, Any]) -> str:
    surface = {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema", tool.get("input_schema")),
    }
    canonical = json.dumps(surface, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class Verdict:
    ok: bool
    reason: str = ""
    newly_pinned: bool = False


class SchemaLock:
    def __init__(self, locks: Dict[str, str], enforce: bool = True, learn: bool = False):
        self.locks = dict(locks or {})
        self.enforce = enforce
        self.learn = learn

    @classmethod
    def load(cls, path: str, enforce: bool = True, learn: bool = False) -> "SchemaLock":
        locks: Dict[str, str] = {}
        try:
            with open(path, "r") as f:
                data = json.load(f)
            locks = {k: v for k, v in (data.get("tools", {}) or {}).items() if v and v != "dummy_hash"}
        except FileNotFoundError:
            logger.warning("Lockfile %s not found.", path)
        return cls(locks, enforce=enforce, learn=learn)

    def check(self, tool: Dict[str, Any]) -> Verdict:
        name = tool.get("name")
        computed = compute_hash(tool)
        expected = self.locks.get(name)

        if expected is None:
            if self.learn:
                self.locks[name] = computed
                return Verdict(ok=True, newly_pinned=True)
            if self.enforce:
                return Verdict(ok=False, reason=f"tool '{name}' is not pinned in the schema lock")
            return Verdict(ok=True)

        if computed != expected:
            return Verdict(ok=False, reason=f"schema drift on '{name}' (expected {expected[:12]}…, got {computed[:12]}…)")
        return Verdict(ok=True)

    def export(self) -> Dict[str, Dict[str, str]]:
        return {"tools": dict(self.locks)}
