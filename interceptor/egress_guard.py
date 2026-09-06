"""
Error normalizer (AG-09 companion).

Kept from V5 because it was one of the good instincts: JSON-RPC errors are
normalized so an upstream tool can't reflect user-supplied data back through the
error channel as a side-band exfiltration path. Response BODY scanning/redaction
now lives in mesh.semantic_waf.SemanticWaf.scan_egress (which redacts spans
instead of destroying the whole payload).
"""
from __future__ import annotations

from typing import Any, Dict


class EgressGuard:
    def sanitize_error(self, error_payload: Dict[str, Any]) -> Dict[str, Any]:
        if "error" in error_payload:
            code = error_payload["error"].get("code", -32603)
            error_payload["error"] = {
                "code": code,
                "message": "Upstream tool execution fault. Details redacted for security.",
            }
        return error_payload
