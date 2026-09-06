"""
Semantic WAF + DLP (AG-08, AG-09).

V5 failures this fixes:
  * RecursiveDecoder decoded every string and FORWARDED the decoded payload
    upstream, corrupting legitimate base64/data and creating a normalization
    mismatch. -> We now decode into a throwaway DETECTION VIEW and forward the
    ORIGINAL bytes untouched.
  * The base64 heuristic fired on any len%4==0 in-charset token ("test","data")
    and mangled it. -> Detection only, and we require the decode to yield mostly
    printable text before considering it, so false positives cost nothing.
  * DLP ran on INGRESS (agent->tool) and blocked legit payment payloads while
    ignoring PII in tool RESPONSES (the real leak path). -> scan_egress() redacts
    PII in responses; ingress DLP is advisory/log by default.
  * The egress guard dropped the ENTIRE response on markers like "======" and
    "```json" (present in normal Markdown/JSON). -> High-confidence injection
    markers only, and we REDACT the offending span, not the whole payload.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Any, Optional, Protocol


# ----------------------------------------------------------------------------
# Detection-only recursive decoder (never mutates the forwarded payload)
# ----------------------------------------------------------------------------
class RecursiveDecoder:
    MAX_DEPTH = 6

    _b64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
    _hex_slash = re.compile(r"\\x([0-9a-fA-F]{2})")
    _uni = re.compile(r"\\u([0-9a-fA-F]{4})")

    @staticmethod
    def _mostly_printable(s: str) -> bool:
        if not s:
            return False
        printable = sum(1 for ch in s if ch.isprintable() or ch in "\t\n\r")
        return printable / len(s) >= 0.9

    @classmethod
    def _decode_once(cls, data: str) -> str:
        out = data
        try:
            u = urllib.parse.unquote(out)
            if u != out:
                out = u
        except Exception:
            pass
        # base64: only if it *decodes to printable text*; otherwise leave as-is.
        if len(out) >= 8 and len(out) % 4 == 0 and cls._b64.match(out):
            try:
                dec = base64.b64decode(out).decode("utf-8")
                if dec != out and cls._mostly_printable(dec):
                    out = dec
            except Exception:
                pass
        if cls._hex_slash.search(out):
            out = cls._hex_slash.sub(lambda m: bytes.fromhex(m.group(1)).decode("utf-8", "ignore"), out)
        if cls._uni.search(out):
            out = cls._uni.sub(lambda m: chr(int(m.group(1), 16)), out)
        return out

    @classmethod
    def detection_view(cls, payload: Any, _budget: list | None = None) -> str:
        """Return a decoded string of all textual content for scanning ONLY.
        Bounded so a crafted deeply-nested payload can't burn CPU (AG-14 adjacent)."""
        if _budget is None:
            _budget = [200_000]  # total chars we will decode/scan
        parts: list[str] = []

        def walk(v: Any):
            if _budget[0] <= 0:
                return
            if isinstance(v, str):
                s = v[: _budget[0]]
                _budget[0] -= len(s)
                cur = s
                for _ in range(cls.MAX_DEPTH):
                    nxt = cls._decode_once(cur)
                    if nxt == cur:
                        break
                    cur = nxt
                parts.append(cur)
            elif isinstance(v, dict):
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)

        walk(payload)
        return "\n".join(parts)


# ----------------------------------------------------------------------------
# Pluggable PII analyzer (Presidio in prod; a stub in tests)
# ----------------------------------------------------------------------------
class PiiAnalyzer(Protocol):
    def find(self, text: str) -> list["PiiSpan"]: ...


class PiiSpan:
    __slots__ = ("entity_type", "start", "end")

    def __init__(self, entity_type: str, start: int, end: int):
        self.entity_type = entity_type
        self.start = start
        self.end = end


class PresidioAnalyzer:
    """Lazy Presidio wrapper. Loaded once per process, not per request."""
    _engine = None

    def __init__(self, entities=("CREDIT_CARD", "US_SSN", "PHONE_NUMBER")):
        self.entities = list(entities)

    def _get(self):
        if PresidioAnalyzer._engine is None:
            from presidio_analyzer import AnalyzerEngine
            PresidioAnalyzer._engine = AnalyzerEngine()
        return PresidioAnalyzer._engine

    def find(self, text: str) -> list[PiiSpan]:
        res = self._get().analyze(text=text, entities=self.entities, language="en")
        return [PiiSpan(r.entity_type, r.start, r.end) for r in res]


class SemanticWaf:
    # Ingress: unambiguous injection / destructive command signatures.
    MALICIOUS = [
        # --- command / shell injection ---
        re.compile(r"(?i)\brm\s+-rf\b"),
        re.compile(r"\$\([^)]*\)"),                          # $(cmd) substitution
        re.compile(r"`[^`]+`"),                              # `cmd` backticks
        re.compile(r"(?i)\|\s*(?:nc|bash|sh|curl|wget|python)\b"),  # pipe to a shell/net tool
        re.compile(r"(?i)&&\s*(?:rm|cat|whoami|reboot|curl|wget|nc)\b"),
        re.compile(r"(?i);\s*(?:rm|cat|curl|wget|nc|bash|sh|reboot)\b"),
        re.compile(r"(?i)\b(?:whoami|reboot|nslookup)\b"),
        re.compile(r"(?i)\bcurl\b[^\n]*(?:\s|=)-d(?:\s|$|=)"),
        re.compile(r"(?i)\bwget\b[^\n]*\bhttp"),
        # --- path traversal / sensitive files ---
        re.compile(r"(?i)/etc/(?:passwd|shadow)"),
        re.compile(r"\.\.[\\/]"),                            # ../ or ..\  traversal
        # --- SQL injection ---
        re.compile(r"(?i)\bDROP\s+TABLE\b"),
        re.compile(r"(?i)\bUNION\s+SELECT\b"),
        re.compile(r"(?i)'\s*OR\s*'?\d"),                    # ' OR '1 / ' OR 1
        re.compile(r"'\s*--"),                               # admin'--
        # --- XSS ---
        re.compile(r"(?i)<\s*script\b[^>]*>[^<]+<\s*/\s*script\s*>"),
        re.compile(r"(?i)\bon(?:error|load|click|mouseover)\s*="),
        re.compile(r"(?i)javascript:"),
        # --- SSRF (cloud metadata / loopback) ---
        re.compile(r"169\.254\.169\.254"),
        re.compile(r"(?i)://(?:localhost|127\.0\.0\.1|\[::1\])"),
        # --- template / expression / log4j injection ---
        re.compile(r"\$\{jndi:"),
        re.compile(r"\{\{.*?\}\}"),
        re.compile(r"#\{.*?\}"),
    ]
    # Egress: HIGH-CONFIDENCE prompt-injection markers only. No "======" / "```json".
    INJECTION_MARKERS = [
        re.compile(r"(?i)\[SYSTEM OVERRIDE\]"),
        re.compile(r"(?i)ignore (all|any) (previous|prior) instructions"),
        re.compile(r"<\|im_start\|>"),
        re.compile(r"(?i)\bdisregard (the )?(above|system) (prompt|instructions)\b"),
    ]

    def __init__(self, analyzer: Optional[PiiAnalyzer] = None, max_bytes: int = 10_000,
                 dlp_enabled: bool = True):
        self.analyzer = analyzer
        self.max_bytes = max_bytes
        self.dlp_enabled = dlp_enabled

    # ---- INGRESS (agent -> tool): detection only, no mutation ----
    def inspect_ingress(self, arguments: Any) -> Optional[str]:
        view = RecursiveDecoder.detection_view(arguments)
        if len(view) > self.max_bytes:
            view = view[: self.max_bytes]  # bound heavy scanning, still scan the head
        for pat in self.MALICIOUS:
            if pat.search(view):
                return f"WAF block: matches '{pat.pattern}'"
        return None

    # ---- EGRESS (tool -> agent): redact, don't destroy ----
    def scan_egress(self, response: dict) -> dict:
        if "result" not in response:
            return response
        try:
            text = json.dumps(response["result"])
        except (TypeError, ValueError):
            return response

        redacted = text
        # 1) High-confidence injection markers: redact the match, keep the rest.
        for pat in self.INJECTION_MARKERS:
            redacted = pat.sub("[REDACTED:INJECTION]", redacted)
        # 2) PII in the RESPONSE (the real exfil path): redact spans.
        #    AG-14: bounded by size, gated by config, and crash-safe — an analyzer
        #    failure must never take down the request/worker.
        if self.dlp_enabled and self.analyzer is not None and len(redacted) <= self.max_bytes:
            try:
                spans = sorted(self.analyzer.find(redacted), key=lambda s: s.start, reverse=True)
                for sp in spans:
                    redacted = redacted[: sp.start] + f"[REDACTED:{sp.entity_type}]" + redacted[sp.end:]
            except Exception:
                import logging
                logging.getLogger("gateway.waf").exception("DLP analyzer failed; passing response through un-redacted-by-NER")

        if redacted != text:
            try:
                response["result"] = json.loads(redacted)
            except (TypeError, ValueError):
                response["result"] = {"redacted": True, "content": redacted}
        return response
