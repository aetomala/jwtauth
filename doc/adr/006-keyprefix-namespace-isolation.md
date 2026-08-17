# ADR-006: KeyPrefix — Namespace Isolation in Redis Backends

**Date**: 2026-04-27  
**Status**: Accepted

## Context

Both Redis store implementations (`RedisKeyStore`, `RedisRefreshStore`) used hardcoded key prefixes with no configuration surface. Any consumer that runs multiple Manager instances against a shared Redis instance — whether for multi-tenancy, environment separation, test isolation, or any other reason — has no way to prevent keyspace collision without resorting to separate Redis clients or separate Redis databases. Neither option is cost-effective at scale.

## Decision

Add an optional `KeyPrefix string` field to `RedisKeyStoreConfig` and `RedisRefreshStoreConfig`. The prefix is prepended to all internally constructed Redis keys. Empty string preserves current behavior exactly — fully backward compatible. The prefix is computed once at construction time into struct-level fields; no call-site concatenation with the raw constant occurs outside the constructor.

The library treats the prefix as an **opaque namespace separator**. It enforces that every Redis operation within a store instance uses the configured prefix consistently — it does not interpret what the prefix means, does not validate its format, and does not prescribe any particular deployment model. What the prefix represents is entirely the consumer's decision.

The full key schema for `RedisRefreshStore` under a given `KeyPrefix` is:

```
[KeyPrefix]tokens:<tokenID>                  — token hash (HSet)
[KeyPrefix]user_tokens:<userID>              — set of tokenIDs for that user (SAdd)
[KeyPrefix]audience_tokens:<aud>             — set of tokenIDs for that audience (SAdd)
[KeyPrefix]audience_user_tokens:<aud>:<uid>  — set of tokenIDs for that user+audience (SAdd)
[KeyPrefix]token_expiry_index                — sorted set of tokenIDs scored by expiry (ZAdd)
```

For `RedisKeyStore`:

```
[KeyPrefix]ks:pem:<keyID>   — PKCS#1 PEM private key (string)
[KeyPrefix]ks:meta:<keyID>  — JSON KeyMetadata (string)
```

An empty `KeyPrefix` preserves the pre-ADR-006 key layout exactly — fully backward compatible.

The other two implementations are out of scope for distinct reasons. `DiskKeyStore` uses a directory path as its natural namespace — two stores with different directories are structurally isolated at the filesystem level with no shared keyspace concern. `MemoryRefreshStore` is designed for development use only; multi-instance namespace isolation is a production deployment concern that does not apply to a development-only implementation.

## Consequences

- Multiple Manager instances can safely share a single Redis instance by using distinct prefixes
- `DiskKeyStore` is unaffected — the directory path already provides structural filesystem-level isolation
- `MemoryRefreshStore` is unaffected — it is designed for development use only; the shared-Redis multi-instance namespace problem is a production concern that does not apply
- Consumers using the empty default need no migration
- `SCAN`-based and `SSCAN`-based operations (`LoadAll`, `ListTokens`, `ListTokensForUser`, `ListTokensForAudience`, `RevokeAllForAudience`) scan only within the configured namespace — operations in one namespace do not observe or affect keys in another. `RedisRefreshStore.Cleanup` no longer scans the token keyspace directly — as of the expiry-indexed rewrite (see #271) it discovers expired tokens via `ZRangeByScore`/`ZRem` against the namespace-scoped `token_expiry_index` key above — but the isolation guarantee is unchanged, since that key is itself `KeyPrefix`-prefixed like every other key in the schema
