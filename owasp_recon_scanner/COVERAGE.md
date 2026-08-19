# Coverage matrix

This is a reconnaissance and control-checking tool. A green result means “no evidence found by these checks,” not “the application is secure.”

| OWASP Top 10:2025 | Automated evidence | Manual review included |
| --- | --- | --- |
| A01 Broken Access Control | Frame protections, public exposure indicators, form heuristics | Authorization matrix, IDOR, force browsing, API object/function authorization |
| A02 Security Misconfiguration | Security headers, directory listings, diagnostics, common exposed files, server disclosure | Infrastructure, cloud, deployment, and environment configuration |
| A03 Software Supply Chain Failures | Third-party script inventory and SRI checks | SBOM, dependency pinning, provenance, CI/CD permissions, update policy |
| A04 Cryptographic Failures | HTTPS/TLS certificate/protocol, HSTS, mixed content, sensitive cache hints | Key management, data classification, encryption at rest, cryptographic design |
| A05 Injection | Error-signature observation; no payloads | Parameterized queries, interpreter boundaries, encoding, approved staging tests |
| A06 Insecure Design | Discovery inventory | Threat model, business logic, abuse cases, rate limits, workflow controls |
| A07 Authentication Failures | Cookie flags, cleartext password forms, auth-looking cache hints | MFA, recovery, session rotation, logout, brute-force resistance |
| A08 Software or Data Integrity Failures | SRI, source-map exposure, backup indicators | Signed artifacts, trusted updates, protected builds, secret scanning |
| A09 Security Logging & Alerting Failures | Not reliably observable over unauthenticated HTTP | Event coverage, tamper resistance, alert routing, retention, monitoring |
| A10 Mishandling of Exceptional Conditions | Error and stack-trace leakage signatures | Fail-closed behavior, transaction safety, production error handling |

API discovery is limited to finding OpenAPI/Swagger-like descriptions. The tool does not claim to verify the OWASP API Security Top 10 without an API-specific, authorized test plan and suitable authentication contexts.
