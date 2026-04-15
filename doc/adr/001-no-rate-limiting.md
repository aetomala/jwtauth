# ADR-001: No Rate Limiting in Library

**Status**: Accepted  
**Date**: 2024-04-01  
**Deciders**: Architecture Team

## Context

Rate limiting is a common requirement for authentication systems. Should jwtauth include rate limiting?

Several factors influenced this decision:

1. **Layer Mismatch**: Rate limiting is most effective at the infrastructure layer (API Gateway, Load Balancer, Ingress) where per-IP, per-route, and per-user limits can be enforced globally.

2. **Deployment Variance**: Rate limiting strategies vary widely:
   - Per-IP limits (stop brute force)
   - Per-user limits (prevent abuse)
   - Per-route limits (protect expensive endpoints)
   - Geographic limits (compliance requirements)

3. **Distributed Challenge**: Application-level rate limiting requires shared state (Redis, distributed counters). This duplicates what API Gateways already provide.

4. **Scope Creep**: jwtauth focuses on token lifecycle management. Rate limiting is a separate concern.

## Decision

**We will NOT include rate limiting in the jwtauth library.**

Users should implement rate limiting at the infrastructure layer:
- API Gateway (Kong, AWS API Gateway, Azure APIM)
- Kubernetes Ingress (nginx.ingress.kubernetes.io/limit-rps)
- Load Balancer
- Cloudflare / CDN

For application-level rate limiting, users can choose from existing Go libraries:
- `golang.org/x/time/rate` (standard library)
- `github.com/ulule/limiter` (Redis-backed)
- `github.com/throttled/throttled` (flexible)

## Consequences

**Positive:**
- Library stays focused on token management
- No forced dependency on Redis or distributed counters
- Users deploy rate limiting where it's most effective (per-route, per-IP)
- Cleaner separation of concerns

**Negative:**
- Users must implement rate limiting separately
- Documentation must guide users toward best practices
- May surprise users who expect "batteries-included" auth library

**Mitigation:**
- Provide clear documentation in doc/DEPLOYMENT.md
- Include examples of API Gateway configuration
- State this boundary clearly in README ("What jwtauth is not")

## References

- Related: ADR-002 (focuses on token lifecycle, not request control)
- See: doc/DEPLOYMENT.md for rate limiting configuration examples
