# Security Policy

## Intended use

Security Test Center is intended only for systems you own or are explicitly authorized to test.

## Built-in controls

- Proof-of-control target verification.
- HTTP/HTTPS-only target policy.
- Port allowlist.
- localhost, link-local, and cloud metadata address blocking.
- Private/reserved IP blocking by default.
- Redirects disabled in probes to reduce SSRF redirect abuse.
- Controlled-load hard limits enforced server-side.
- No raw packet flood, spoofing, amplification, credential attack, exploit payload generator, or verification bypass.

## Reporting a vulnerability

Do not include real credentials, private keys, production secrets, or customer data in issue reports.
