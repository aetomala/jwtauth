# Security Policy

## Supported Versions

| Version | Support |
|---------|---------|
| v0.5.x (active development) | Full — features and security fixes |
| v0.4.x | Security fixes only |
| < v0.4.0 | None |

---

## Reporting a Vulnerability

Report security vulnerabilities **privately** via GitHub's Security Advisory feature:

1. Navigate to the repository → **Security** tab → **Advisories** → **Report a vulnerability**
2. Include: affected version(s), reproduction steps, and an impact assessment
3. Do not open a public issue — the private advisory keeps the report confidential until a patch is ready

**Expected response timeline**: acknowledgement within 72 hours; patch timeline communicated within 7 days of confirmation.

---

## Coordinated Disclosure Policy

- Vulnerabilities are patched privately and disclosed publicly after a fix is released.
- A CVE is requested for confirmed vulnerabilities with CVSS score ≥ 7.0.
- Reporters are credited in the release notes unless they prefer anonymity.

---

## Scope

### In Scope

| Area | Package |
|------|---------|
| JWT signing and validation logic | `pkg/tokens` |
| Key management and rotation | `pkg/keys` |
| Token storage and revocation | `pkg/storage` |
| Observability interfaces | `pkg/logging`, `pkg/metrics`, `pkg/tracing` |

### Out of Scope

The following are **infrastructure or application concerns** and are explicitly out of scope for this library:

- **Rate limiting** — must be applied at the API Gateway or Ingress layer; see [ADR-001](doc/adr/001-no-rate-limiting.md) and the [Rate Limiting](doc/DEPLOYMENT.md#rate-limiting) section of the Deployment Guide.
- **Middleware** — request handling, authentication flows, and session management are the responsibility of the calling application.
- **Redis hardening** — TLS, ACL configuration, and network isolation are deployment-side controls; see [Redis Security Hardening](doc/DEPLOYMENT.md#redis-security-hardening) in the Deployment Guide.
- **Key storage permissions** — filesystem and OS-level controls on `DiskKeyStore` directories are the operator's responsibility.

Vulnerabilities in these areas should be reported to the maintainers of the relevant infrastructure or framework.

---

## Security Design Decisions

The following Architecture Decision Records document the security-relevant design choices made in this library:

| ADR | Decision |
|-----|----------|
| [ADR-001](doc/adr/001-no-rate-limiting.md) | No rate limiting in the library — infrastructure concern |
| [ADR-003](doc/adr/003-rs256-only.md) | RS256-only signing — algorithm confusion attacks (CVE-2015-9235) prevented by design |
| [ADR-004](doc/adr/004-kid-validation.md) | `kid` UUID v4 validation — path traversal via `kid` is structurally impossible |
| [ADR-005](doc/adr/005-security-boundaries.md) | Attacker-controlled token field trust model — every field is untrusted until its validation gate |
| [ADR-008](doc/adr/008-reserved-claims-at-issuance.md) | Reserved claims protection at issuance — `sub`, `iss`, `aud`, `exp`, `nbf`, `iat`, `jti` cannot be overridden via `CustomClaims` |
