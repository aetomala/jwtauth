# audience-revocation

Demonstrates multi-audience token issuance and audience-scoped revocation using
`RevokeAllForAudience`, `RevokeAllForUserAndAudience`, and `ListTokensForAudience`.
Run it to see how a single refresh token spanning multiple audiences is revoked as
an atomic unit — and how to target revocation by audience, or by user and audience.

## Project Structure

```
audience-revocation/
├── main.go   — issues multi-audience tokens, lists, revokes, and verifies atomicity
└── go.mod
```

## Setup

```bash
go mod download
```

No external services required — the example uses `DiskKeyStore` and `MemoryRefreshStore`.

## Running

```bash
go run .
```

Expected output:

```
Issued tokens:
  alice — audiences: [svc-payments svc-reports]
  bob   — audiences: [svc-reports]

=== ListTokensForAudience("svc-payments") ===
  tokenRef=22d7dd9d2f9628cc userID=alice  audiences=[svc-payments svc-reports] revoked=false

=== RevokeAllForAudience("svc-payments") ===
  Revoked all tokens touching svc-payments

=== Atomicity check: refresh with alice's revoked token ===
time=2026-09-29T12:54:28.025-04:00 level=WARN msg="retrieve: token has been revoked" tokenRef=22d7dd9d2f9628cc userID=alice
time=2026-09-29T12:54:28.025-04:00 level=WARN msg="refresh token not found in store" error="refresh token has been revoked"
  RefreshAccessToken → ErrTokenRevoked (expected)

=== ListTokensForAudience("svc-reports") after svc-payments revocation ===
  tokenRef=22d7dd9d2f9628cc userID=alice  audiences=[svc-payments svc-reports] revoked=true
  tokenRef=456c48dd52df6331 userID=bob    audiences=[svc-reports] revoked=false

=== RevokeAllForUserAndAudience("bob", "svc-reports") ===
  Revoked bob's svc-reports tokens

=== Final state: ListTokensForAudience("svc-reports") ===
  tokenRef=22d7dd9d2f9628cc userID=alice  audiences=[svc-payments svc-reports] revoked=true
  tokenRef=456c48dd52df6331 userID=bob    audiences=[svc-reports] revoked=true
Done.
```

Token references and timestamps differ on every run. Each token is shown as a `tokenRef`
— the first 16 hex characters of its SHA-256 digest, never any part of the token itself.
It is the same value jwtauth writes under `tokenRef` in its own logs: the library's `WARN`
line above carries alice's reference, so a printed token can be matched to log entries.

## How It Works

**Atomicity (ADR-009):** A refresh token is a single revocable unit. When alice's token
covers `["svc-payments", "svc-reports"]`, revoking by `"svc-payments"` revokes the entire
token — there is no per-audience revocation flag. Operators who need independent
per-audience revocability should issue separate tokens per audience at issuance time.

**Access token window:** The access token alice holds at revocation time remains technically
valid until its TTL expires — jwtauth does not perform JTI-based replay prevention for
access tokens (ADR-010). Use a short access token TTL to bound the window. For tighter
containment, add a JTI deny-list check in middleware before calling `ValidateAccessToken`.

**Cursor semantics (ADR-011):** `ListTokensForAudience` returns revoked tokens in the
listing — filter on `tok.Revoked` as needed. Page size is a hint; cursors are opaque.

## Next Steps

See [Audience-Scoped Revocation](../../doc/DEPLOYMENT.md#audience-scoped-revocation) in
DEPLOYMENT.md for operational patterns and bulk-revocation workflows.
