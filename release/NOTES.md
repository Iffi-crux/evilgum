EvilGum 0.1.0rc1 is the first packaged developer-beta candidate for one isolated Linux amd64 deployment, one gateway worker and a stateless JSON MCP upstream.

Download the quickstart ZIP for the wheel, source, hash-locked dependencies and synthetic allow/deny/recovery walkthrough. Read its README before running it. Production setup requires a trusted issuer, approved pins/grants, TLS and durable storage.

This release adds scoped MCP transport, durable enforcement state, strict DLP, recovery epochs, backup/restore and a non-root container. The attached verification evidence describes exactly which tests ran. One optional value-mode limitation remains an expected failure; production requires coarse taint.

This is an open-source core release. Enterprise management/SSO deployment remains a separate validation track. Independent onboarding and broader client compatibility are still pending. No customer activations or third-party security certification are claimed.

Please report non-sensitive setup problems through repository issues; security reports go privately to the contact in SECURITY.md. Never attach credentials or unredacted sensitive data.
