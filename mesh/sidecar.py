"""
Capability tokens with real cryptographic attenuation (AG-04).

V5's MacaroonEvaluator took a root_key it NEVER used, and "verified" caveats that
arrived as comma-split plaintext in a client-controlled header. There was nothing
to forge because there was no signature. This is a genuine macaroon:

  sig_0        = HMAC(root_key, identifier)
  sig_{i+1}    = HMAC(sig_i, caveat_i)

Every caveat is folded into the chain, so a client cannot add, drop, reorder or
weaken a caveat without invalidating the final signature. verify() recomputes the
chain and constant-time compares before any caveat is trusted. Only then do we
evaluate first-party caveats (monotonic attenuation, path-segment resource scope).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Dict, List, Tuple


class SecurityError(Exception):
    pass


PRIVILEGE_LEVELS = {"deny": 0, "read": 1, "write": 2, "admin": 3}


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class Macaroon:
    """Minimal, correct macaroon: identifier + ordered caveats + HMAC chain sig."""

    def __init__(self, identifier: str, caveats: List[str], signature: bytes):
        self.identifier = identifier
        self.caveats = caveats
        self.signature = signature

    @staticmethod
    def _chain(root_key: bytes, identifier: str, caveats: List[str]) -> bytes:
        sig = hmac.new(root_key, identifier.encode("utf-8"), hashlib.sha256).digest()
        for c in caveats:
            sig = hmac.new(sig, c.encode("utf-8"), hashlib.sha256).digest()
        return sig

    @classmethod
    def mint(cls, root_key: bytes, identifier: str, caveats: List[str] | None = None) -> "Macaroon":
        caveats = list(caveats or [])
        return cls(identifier, caveats, cls._chain(root_key, identifier, caveats))

    def attenuate(self, caveat: str) -> "Macaroon":
        """Append a caveat, extending the HMAC chain (only holder can do this correctly)."""
        new_sig = hmac.new(self.signature, caveat.encode("utf-8"), hashlib.sha256).digest()
        return Macaroon(self.identifier, self.caveats + [caveat], new_sig)

    def serialize(self) -> str:
        return _b64e(json.dumps(
            {"i": self.identifier, "c": self.caveats, "s": _b64e(self.signature)},
            separators=(",", ":"),
        ).encode("utf-8"))

    @classmethod
    def deserialize(cls, token: str) -> "Macaroon":
        try:
            obj = json.loads(_b64d(token))
            return cls(obj["i"], list(obj["c"]), _b64d(obj["s"]))
        except Exception as e:
            raise SecurityError("malformed macaroon token") from e


class MacaroonEvaluator:
    def __init__(self, root_key: bytes):
        if not root_key or len(root_key) < 16:
            raise ValueError("macaroon root_key must be >= 16 bytes")
        self.root_key = root_key

    def verify(self, token: str) -> Dict[str, str]:
        """Verify signature FIRST, then evaluate caveats. Raises SecurityError on any failure."""
        mac = Macaroon.deserialize(token)
        expected = Macaroon._chain(self.root_key, mac.identifier, mac.caveats)
        if not hmac.compare_digest(expected, mac.signature):
            raise SecurityError("macaroon signature verification failed (tampered or forged caveats)")
        return self._evaluate(mac.caveats)

    def _evaluate(self, caveats: List[str]) -> Dict[str, str]:
        state: Dict[str, str] = {}
        for caveat in caveats:
            key, val = self._parse(caveat)
            if key not in state:
                state[key] = val
                continue
            if key == "action":
                cur = PRIVILEGE_LEVELS.get(state[key], 0)
                new = PRIVILEGE_LEVELS.get(val, 0)
                if new > cur:
                    raise SecurityError(f"illegal privilege expansion: {state[key]} -> {val}")
                state[key] = val
            elif key == "resource":
                if not self._path_contains(state[key], val):
                    raise SecurityError(f"resource '{val}' escapes scope '{state[key]}'")
                state[key] = val
            else:
                if state[key] != val:
                    raise SecurityError(f"conflicting caveat {key}={val}")
        return state

    @staticmethod
    def _parse(caveat: str) -> Tuple[str, str]:
        parts = caveat.split("=", 1)
        if len(parts) != 2:
            raise SecurityError(f"malformed caveat: {caveat}")
        return parts[0].strip(), parts[1].strip()

    @staticmethod
    def _path_contains(scope: str, candidate: str) -> bool:
        """Path-SEGMENT containment, not string prefix. '/data' contains '/data/x'
        but NOT '/database' or '/data-secret' (the V5 startswith bug)."""
        s = [p for p in scope.strip("/").split("/") if p]
        c = [p for p in candidate.strip("/").split("/") if p]
        if ".." in c:
            return False
        return c[: len(s)] == s
