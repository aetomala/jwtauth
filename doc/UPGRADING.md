# Upgrading jwtauth

This document describes breaking changes and the steps required to upgrade between versions.

## Unreleased (v0.4.0 → next)

### `storage.RefreshStore` — two new required methods

`ListTokens` and `ListTokensForUser` have been added to the `RefreshStore` interface.
Any custom implementation that only satisfies the old interface will fail to compile.

#### `ListTokens(ctx context.Context, cursor string, count int) ([]*RefreshToken, string, error)`

Returns a page of all refresh tokens in the store, starting from `cursor`.
Pass `""` to begin from the start. Returns the next cursor and a `nil` error on success.
Returns `""` as the next cursor when iteration is exhausted.
`count` is a hint — the actual page size may vary.

All tokens are returned regardless of revocation or expiry status — the caller is responsible for filtering.
Cursor semantics are best-effort: tokens created or deleted between pages may appear, disappear, or shift.

**Migration**: Add the method to every custom `RefreshStore` implementation:

```go
func (s *MyStore) ListTokens(ctx context.Context, cursor string, count int) ([]*storage.RefreshToken, string, error) {
    // Your implementation here.
    // Return next cursor as "" when exhausted.
}
```

#### `ListTokensForUser(ctx context.Context, userID string, cursor string, count int) ([]*RefreshToken, string, error)`

Returns a page of refresh tokens belonging to `userID`, starting from `cursor`.
Returns `ErrInvalidUserID` if `userID` is empty or whitespace.
All other semantics are identical to `ListTokens`.

**Migration**: Add the method to every custom `RefreshStore` implementation:

```go
func (s *MyStore) ListTokensForUser(ctx context.Context, userID string, cursor string, count int) ([]*storage.RefreshToken, string, error) {
    if strings.TrimSpace(userID) == "" {
        return nil, "", storage.ErrInvalidUserID
    }
    // Your implementation here.
}
```

#### Compile-time assertion

Add a compile-time assertion to catch missed implementations early:

```go
var _ storage.RefreshStore = (*MyStore)(nil)
```

---

## v0.3.x → v0.4.0 (In Progress)

No breaking changes documented yet for this transition beyond the items above.
