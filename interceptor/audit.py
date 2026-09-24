"""
Tamper-evident audit log (MCP08, API-inventory / compliance).

Every security decision is appended as a hash-chained JSONL record:

    hash_n = SHA256( hash_{n-1} || seq || ts || canonical(event) )

Each entry commits to the preceding hash. Verification detects internal edits,
gaps and reordering. This unkeyed local chain cannot prove completeness or detect
suffix truncation / an entirely rewritten chain without a trusted external head.
Ship checkpoints to independently protected storage for that stronger guarantee.

Production requires a durable forward-intent append before upstream execution.
"""
from __future__ import annotations

import os
import json
import time
import hashlib
import threading
from typing import Any, Dict, Optional, Callable

GENESIS = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    def __init__(self, path: str = "data/audit.log.jsonl",
                 forward: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.path = path
        self.forward = forward                 # optional SIEM sink
        self._lock = threading.Lock()
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._prev, self._seq = self._resume()

    def _resume(self):
        prev, seq = GENESIS, 0
        if os.path.exists(self.path) and not self.verify(self.path)["ok"]:
            raise RuntimeError("Audit integrity check failed; refusing to append")
        try:
            with open(self.path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    prev, seq = rec["hash"], rec["seq"] + 1
        except FileNotFoundError:
            pass
        return prev, seq

    def append(self, event: Dict[str, Any]) -> str:
        with self._lock:
            ts = time.time()
            seq = self._seq
            digest = hashlib.sha256(
                (self._prev + str(seq) + repr(ts) + _canonical(event)).encode("utf-8")
            ).hexdigest()
            record = {"seq": seq, "ts": ts, "prev": self._prev, "hash": digest, "event": event}
            with open(self.path, "a") as f:
                f.write(_canonical(record) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._prev, self._seq = digest, seq + 1
            if self.forward:
                try:
                    self.forward(record)
                except Exception:
                    pass
            return digest

    @staticmethod
    def verify(path: str) -> Dict[str, Any]:
        """Recompute the chain; report the first break if any."""
        with open(path, "r") as f:
            return AuditLog.verify_lines(f)

    @staticmethod
    def verify_lines(lines) -> Dict[str, Any]:
        """Verify exactly the supplied snapshot; shared by operational reports."""
        prev, count = GENESIS, 0
        for lineno, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("seq") != count:
                return {"ok": False, "broken_at_line": lineno, "reason": "sequence mismatch"}
            if rec.get("prev") != prev:
                return {"ok": False, "broken_at_line": lineno, "reason": "prev-hash mismatch"}
            recomputed = hashlib.sha256(
                (prev + str(rec["seq"]) + repr(rec["ts"]) + _canonical(rec["event"])).encode("utf-8")
            ).hexdigest()
            if recomputed != rec.get("hash"):
                return {"ok": False, "broken_at_line": lineno, "reason": "hash mismatch (record altered)"}
            prev = rec["hash"]
            count += 1
        return {"ok": True, "records": count, "head": prev}
