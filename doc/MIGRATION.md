# Migration Guide

This guide helps you migrate from other JWT libraries to jwtauth.

---

## Migrating from golang-jwt/jwt

### What You're Currently Doing

```go
import "github.com/golang-jwt/jwt/v5"

// You manage keys manually
privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
publicKey := &privateKey.PublicKey

// You sign tokens yourself
claims := jwt.MapClaims{
    "sub": userID,
    "exp": time.Now().Add(15 * time.Minute).Unix(),
}
token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
tokenString, _ := token.SignedString(privateKey)

// You validate tokens yourself
parsed, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    return publicKey, nil
})
```

**What you handle manually:**
- Key generation and storage
- Key rotation (if you do it at all)
- Refresh token storage
- Revocation logic

### Migrating to jwtauth

```go
import (
    "github.com/aetomala/jwtauth/pkg/keys"
    "github.com/aetomala/jwtauth/pkg/storage"
    "github.com/aetomala/jwtauth/pkg/tokens"
)

// Step 1: Create KeyManager (handles keys + rotation)
ks, _ := keys.NewDiskKeyStore("./keys", 2048, nil, nil)
km, _ := keys.NewManager(keys.KeyManagerConfig{
    KeyStore:            ks,
    KeyRotationInterval: 30 * 24 * time.Hour,
    KeyOverlapDuration:  1 * time.Hour,
})

// Step 2: Create RefreshStore (handles refresh tokens)
refreshStore := storage.NewMemoryRefreshStore(nil, nil)

// Step 3: Create TokenManager (coordinates everything)
mgr, _ := tokens.NewManager(tokens.ManagerConfig{
    KeyManager:           km,
    RefreshStore:         refreshStore,
    AccessTokenDuration:  15 * time.Minute,
    RefreshTokenDuration: 30 * 24 * time.Hour,
    Issuer:               "my-app",
    Audience:             []string{"my-app-api"},
})

// Step 4: Start lifecycle
ctx := context.Background()
km.Start(ctx)
mgr.Start(ctx)
defer km.Shutdown(ctx)
defer mgr.Shutdown(ctx)

// Now: Issue tokens (access + refresh in one call)
accessToken, refreshToken, _ := mgr.IssueTokenPair(ctx, userID)

// Later: Validate tokens
claims, _ := mgr.ValidateAccessToken(ctx, accessToken)

// Later: Refresh access token
newAccessToken, _ := mgr.RefreshAccessToken(ctx, refreshToken)

// On logout: Revoke all sessions
mgr.RevokeAllUserTokens(ctx, userID)
```

**What jwtauth handles for you:**
- ✅ Key rotation (automatic, zero-downtime)
- ✅ Refresh token storage (memory or Redis)
- ✅ Revocation (instant, not expiry-based)
- ✅ Background cleanup
- ✅ Observability (optional logging/metrics)

---

## Migrating from gin-jwt

### What You're Currently Doing

```go
import "github.com/appleboy/gin-jwt/v2"

// Gin-specific middleware configuration
authMiddleware, _ := jwt.New(&jwt.GinJWTMiddleware{
    Realm:       "test zone",
    Key:         []byte("secret key"),
    Timeout:     time.Hour,
    MaxRefresh:  time.Hour,
    IdentityKey: "userID",
    PayloadFunc: func(data interface{}) jwt.MapClaims {
        return jwt.MapClaims{"userID": data}
    },
    Authenticator: func(c *gin.Context) (interface{}, error) {
        // Your login logic
    },
})

// Routes are tied to Gin
router.POST("/login", authMiddleware.LoginHandler)
router.Use(authMiddleware.MiddlewareFunc())
```

**Limitations:**
- ❌ Framework lock-in (Gin only)
- ❌ No key rotation
- ❌ No revocation
- ❌ Single-instance only (state in memory)

### Migrating to jwtauth

jwtauth is framework-agnostic. You write the middleware yourself (20 lines):

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/aetomala/jwtauth/pkg/tokens"
)

// Create TokenManager once at startup (see golang-jwt migration above)
var mgr *tokens.Manager

// Your middleware (framework-agnostic logic)
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(401, gin.H{"error": "missing_token"})
            c.Abort()
            return
        }

        token := strings.TrimPrefix(authHeader, "Bearer ")
        claims, err := mgr.ValidateAccessToken(c.Request.Context(), token)
        if err != nil {
            c.JSON(401, gin.H{"error": "invalid_token"})
            c.Abort()
            return
        }

        c.Set("userID", claims.Subject)
        c.Next()
    }
}

// Routes
router.POST("/login", LoginHandler)  // You implement login
router.Use(AuthMiddleware())         // Your middleware
```

**Benefits:**
- ✅ Works with any framework (Gin, Echo, Chi, stdlib)
- ✅ Key rotation built in
- ✅ Refresh tokens with revocation
- ✅ Distributed-ready (Redis backend)
- ✅ 20 lines you own and control

**See also:** `examples/gin-example/` for complete working example

---

## Migrating from jwx

### What You're Currently Doing

```go
import "github.com/lestrrat-go/jwx/v2/jwt"

// You use jwx for its comprehensive JOSE support
token, _ := jwt.NewBuilder().
    Subject(userID).
    Issuer("my-app").
    Expiration(time.Now().Add(15 * time.Minute)).
    Build()

signed, _ := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
```

**jwx strengths:**
- Full JOSE suite (JWS, JWE, JWK, JWA)
- Multiple algorithms
- Encrypted tokens (JWE)

### When to Use jwtauth vs. jwx

**Use jwtauth if:**
- You only need RS256 JWT tokens (not JWE)
- You want stateful refresh tokens + revocation
- You want automatic key rotation
- You want production observability (metrics, logging)

**Stay with jwx if:**
- You need JWE (encrypted tokens)
- You need multiple signing algorithms (ES256, EdDSA, etc.)
- You need detached payloads or nested tokens

**Migration approach:**

jwtauth uses RS256 only. If that's sufficient:

```go
// Replace jwx token builder with jwtauth
mgr, _ := tokens.NewManager(config)  // See golang-jwt migration

// Issue tokens
accessToken, refreshToken, _ := mgr.IssueTokenPair(ctx, userID)

// Validate tokens
claims, _ := mgr.ValidateAccessToken(ctx, accessToken)
```

If you need JWE or multiple algorithms, **don't migrate** — jwx is the right tool.

---

## Common Migration Patterns

### Pattern 1: Adding Refresh Tokens

**Before (stateless):**
```go
// Issue 15-minute access token
// User must re-authenticate when it expires
```

**After (stateful):**
```go
// Issue both tokens
accessToken, refreshToken, _ := mgr.IssueTokenPair(ctx, userID)

// Client stores refreshToken securely
// When accessToken expires, client calls:
newAccessToken, _ := mgr.RefreshAccessToken(ctx, refreshToken)
```

### Pattern 2: Adding Revocation

**Before (expiry-based):**
```go
// Issue token with 15-minute expiry
// No way to revoke early — must wait 15 minutes
```

**After (instant revocation):**
```go
// On logout or password change:
mgr.RevokeAllUserTokens(ctx, userID)

// All refresh tokens invalidated immediately
// Access tokens expire in 15 minutes (or shorter if you reduce duration)
```

### Pattern 3: Key Rotation

**Before (manual):**
```go
// Generate new key manually
// Deploy new key
// Hope old tokens still validate (they won't)
```

**After (zero-downtime):**
```go
km, _ := keys.NewManager(keys.KeyManagerConfig{
    KeyStore:            ks,
    KeyRotationInterval: 30 * 24 * time.Hour, // Auto-rotate every 30 days
    KeyOverlapDuration:  1 * time.Hour,        // Old key valid for 1 hour
})

// Automatic rotation:
// Day 0:     Key A signs, Key A validates
// Day 30:    Rotate → Key B signs, Key A+B validate (overlap)
// Day 30+1h: Key B signs, Key B validates
```

---

## Deployment Considerations

### Single-Instance → Distributed

**Development/Single-Instance:**
```go
// Use in-memory storage
ks, _ := keys.NewDiskKeyStore("./keys", 2048, nil, nil)
refreshStore := storage.NewMemoryRefreshStore(nil, nil)
```

**Production/Multi-Instance:**
```go
// Use Redis for shared state
import "github.com/redis/go-redis/v9"

client := redis.NewClient(&redis.Options{Addr: "redis:6379"})

// Shared key storage
ks, _ := keys.NewRedisKeyStore(client, logger, metrics)

// Shared refresh token storage
refreshStore := storage.NewRedisRefreshStore(client, logger, metrics)
```

**No code changes** — just swap the storage backend.

---

## Migration Checklist

- [ ] Create KeyManager with appropriate KeyStore (Disk or Redis)
- [ ] Create RefreshStore (Memory or Redis)
- [ ] Create TokenManager with config
- [ ] Update login endpoint to issue token pairs (IssueTokenPair)
- [ ] Add refresh endpoint (RefreshAccessToken)
- [ ] Add logout endpoint (RevokeRefreshToken or RevokeAllUserTokens)
- [ ] Update auth middleware to validate tokens (ValidateAccessToken)
- [ ] Start lifecycle in main() (Start) and defer shutdown (Shutdown)
- [ ] Test token issuance, validation, refresh, revocation
- [ ] Add observability (optional Logger, Metrics)

---

## Need Help?

- See `examples/` directory for complete working examples (Chi, Gin, Echo)
- Read `doc/ARCHITECTURE.md` for design rationale
- Check `doc/DEPLOYMENT.md` for production deployment patterns

---

**Migration support:** If you're stuck, open an issue at https://github.com/aetomala/jwtauth/issues
