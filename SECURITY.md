# Security policy

0.1.0rc1 is a developer beta candidate, not a generally available production release. The supported test/deployment profile is one isolated customer, one worker, local SQLite storage, Linux amd64/Python 3.11, MCP 2025-11-25 stateless JSON HTTP. See MCP-COMPATIBILITY.md and PHASE1-OPERATIONS.md. Other versions have no maintenance promise from this candidate.

Report vulnerabilities privately to info@faseel.app, the project's existing contact. Do not post credentials or exploit details in public issues. Contact delivery and response commitments have not been verified during release preparation.

Local tests and synthetic recovery drills are engineering evidence, not independent security certification. Historical benchmark percentages are not claims for this release. No third-party penetration test was performed here.

Production requires trusted asymmetric JWT issuance with the deployment eg_epoch claim, reviewed tenant grants and pins, coarse taint, enforce mode, DLP, verified upstream TLS, durable local storage and one worker. Configure TLS ingress before exposing remote traffic. Never expose admin/metrics without the intended access controls.

Known limits: pins compare declared metadata, not implementation; changes are detected when listed. Coarse taint is conservative and persists until a fresh trusted session. Optional value mode has a known re-encoding limitation and is disallowed in production. Audit chaining alone cannot detect full rewrites or suffix removal without an external checkpoint. No shared SaaS, HA, broad MCP host compatibility or universal exfiltration prevention claim is made.

Track public non-sensitive defects at https://github.com/Iffi-crux/evilgum/issues. Security fixes belong in the open core and are not reserved for enterprise.
