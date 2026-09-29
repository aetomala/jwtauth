# token-audit

Demonstrates cursor-based token enumeration using `ListTokens` and `ListTokensForUser`. Run it to see how to walk a full token inventory page by page — useful for compliance exports, session dashboards, and bulk-revocation pipelines.

## Project Structure

```
token-audit/
├── main.go   — seeds tokens, then paginates with ListTokens and ListTokensForUser
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
Seeded 6 refresh tokens for 3 users

=== Global token audit (ListTokens, pageSize=2) ===
  [page 1] tokenRef=36e2703d708d85b4 userID=carol revoked=false
  [page 1] tokenRef=3fd1eaf7e29b784d userID=bob revoked=false
  [page 2] tokenRef=e15e2018ec7084a2 userID=alice revoked=false
  [page 2] tokenRef=e48c094f202d97b9 userID=alice revoked=false
  [page 3] tokenRef=ec433e2988616d4e userID=bob revoked=false
  [page 3] tokenRef=ed72523ec4ba804b userID=alice revoked=false
Total tokens: 6

=== User-scoped audit for "alice" (ListTokensForUser, pageSize=2) ===
  [page 1] tokenRef=e48c094f202d97b9 expires=2026-10-06T16:53:40Z
  [page 1] tokenRef=ed72523ec4ba804b expires=2026-10-06T16:53:40Z
  [page 2] tokenRef=e15e2018ec7084a2 expires=2026-10-06T16:53:40Z
Total tokens for "alice": 3
```

Token references, their order, and expiry times differ on every run. Each token is shown as
a `tokenRef` — the first 16 hex characters of its SHA-256 digest, never any part of the token
itself. It is the same value jwtauth writes under `tokenRef` in its own logs, so an audited
token can be matched to log entries.

## How It Works

`ListTokens(ctx, cursor, pageSize)` returns one page of tokens from the store. Pass `""` as the
cursor to start from the beginning; the returned `next` cursor is passed to the next call. When
`next` is `""`, the full inventory has been traversed.

Key semantics to understand:

- **All tokens returned** — tokens are included regardless of expiry or revocation status. Filter
  on `tok.ExpiresAt` or `tok.Revoked` as needed for your use case.
- **Page size is a hint** — the store may return fewer items per page than requested.
- **Best-effort cursors** — tokens created or deleted concurrently between pages may appear,
  disappear, or shift. For a strict snapshot, quiesce writes before auditing.

`ListTokensForUser` is identical but scoped to a single `userID`. It returns
`storage.ErrInvalidUserID` if `userID` is empty or whitespace.

## Next Steps

See the [Token Enumeration](../../doc/DEPLOYMENT.md#token-enumeration) section in DEPLOYMENT.md
for operational patterns including bulk revocation and compliance export pipelines.
