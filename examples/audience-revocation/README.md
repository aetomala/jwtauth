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
  tokenID=3f8a1b2c… userID=alice   audiences=[svc-payments svc-reports] revoked=false

=== RevokeAllForAudience("svc-payments") ===
  Revoked all tokens touching svc-payments

=== Atomicity check: refresh with alice's revoked token ===
  RefreshAccessToken → ErrTokenRevoked (expected)

=== ListTokensForAudience("svc-reports") after svc-payments revocation ===
  tokenID=3f8a1b2c… userID=alice   audiences=[svc-payments svc-reports] revoked=true
  tokenID=a7c2d9e1… userID=bob     audiences=[svc-reports] revoked=false

=== RevokeAllForUserAndAudience("bob", "svc-reports") ===
  Revoked bob's svc-reports tokens

=== Final state: ListTokensForAudience("svc-reports") ===
  tokenID=3f8a1b2c… userID=alice   audiences=[svc-payments svc-reports] revoked=true
  tokenID=a7c2d9e1… userID=bob     audiences=[svc-reports] revoked=true
Done.
```

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
