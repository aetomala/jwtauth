package tokens

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ============================================================================
// JWT CLAIMS - Complete Type Definitions
// ============================================================================

// Claims represents the complete set of JWT claims for access tokens.
//
// This combines:
//   - Standard JWT claims (from RFC 7519)
//   - Custom application-specific claims
//
// Usage in IssueAccessToken:
//
//	claims := &Claims{
//	    RegisteredClaims: jwt.RegisteredClaims{
//	        Subject:   userID,
//	        Issuer:    "auth.example.com",
//	        ExpiresAt: jwt.NewNumericDate(expiresAt),
//	    },
//	    Custom: map[string]interface{}{
//	        "role": "admin",
//	    },
//	}
type Claims struct {
	// Embed standard JWT claims
	jwt.RegisteredClaims

	// Custom application-specific claims
	// Examples: role, permissions, tenant, email, etc.
	Custom map[string]interface{} `json:"-"` // Not serialized directly
}

// ============================================================================
// STANDARD JWT CLAIMS (from golang-jwt/jwt library)
// ============================================================================

// RegisteredClaims is defined by the jwt library as:
//
// type RegisteredClaims struct {
//     Issuer    string           `json:"iss,omitempty"`
//     Subject   string           `json:"sub,omitempty"`
//     Audience  ClaimStrings     `json:"aud,omitempty"`
//     ExpiresAt *NumericDate     `json:"exp,omitempty"`
//     NotBefore *NumericDate     `json:"nbf,omitempty"`
//     IssuedAt  *NumericDate     `json:"iat,omitempty"`
//     ID        string           `json:"jti,omitempty"`
// }
//
// We use this directly from the jwt library.

// ============================================================================
// CLAIM FIELD EXPLANATIONS
// ============================================================================

// Standard Claims (RegisteredClaims):
//
// 1. Subject (sub) - string
//    - Who the token is for
//    - Usually user ID or email
//    - Example: "user-12345", "user@example.com"
//
// 2. Issuer (iss) - string
//    - Who issued the token
//    - Your authentication service URL
//    - Example: "https://auth.example.com"
//
// 3. Audience (aud) - []string
//    - Who can use the token
//    - List of services that accept this token
//    - Example: ["api.example.com", "web.example.com"]
//
// 4. ExpiresAt (exp) - *NumericDate
//    - When token becomes invalid
//    - Unix timestamp
//    - Example: 1704067200 (2024-01-01 10:15:00 UTC)
//
// 5. IssuedAt (iat) - *NumericDate
//    - When token was created
//    - Unix timestamp
//    - Example: 1704063600 (2024-01-01 10:00:00 UTC)
//
// 6. NotBefore (nbf) - *NumericDate
//    - Token not valid before this time
//    - Unix timestamp
//    - Usually same as IssuedAt
//
// 7. ID (jti) - string
//    - Unique token identifier
//    - Used for revocation/tracking
//    - Example: "xF7hN2kP9mQ8rT4vL6wY3g"

// ============================================================================
// CUSTOM CLAIMS EXAMPLES
// ============================================================================

// Example custom claims you might add:
//
// 1. Role-Based Access Control:
//    "role": "admin"
//    "permissions": ["read", "write", "delete"]
//
// 2. Multi-Tenancy:
//    "tenant": "org-12345"
//    "tenant_role": "owner"
//
// 3. User Information:
//    "email": "user@example.com"
//    "username": "johndoe"
//    "name": "John Doe"
//
// 4. Session Information:
//    "session_id": "sess-abc123"
//    "device_id": "device-xyz789"
//
// 5. Scopes (OAuth2-style):
//    "scope": "read:users write:posts"

// ============================================================================
// HELPER TYPES
// ============================================================================

// TokenMetadata contains information about a token for introspection.
// This is what you return when someone asks "tell me about this token".
type TokenMetadata struct {
	// Active indicates if the token is currently valid
	Active bool `json:"active"`

	// Subject is the user ID from the token
	Subject string `json:"sub,omitempty"`

	// TokenType indicates what kind of token this is
	TokenType string `json:"token_type,omitempty"` // "access" or "refresh"

	// ExpiresAt is when the token expires
	ExpiresAt time.Time `json:"exp,omitempty"`

	// IssuedAt is when the token was created
	IssuedAt time.Time `json:"iat,omitempty"`

	// Issuer is who issued the token
	Issuer string `json:"iss,omitempty"`

	// Audience is who can use the token
	Audience []string `json:"aud,omitempty"`

	// Scope contains OAuth2 scopes if present
	Scope string `json:"scope,omitempty"`

	// Custom contains any custom claims
	Custom map[string]interface{} `json:"custom,omitempty"`
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

// ValidateClaims checks if claims are valid at the given time.
//
// Validates:
//   - Token not expired (exp)
//   - Token active (nbf)
//   - Required fields present
func ValidateClaims(claims *jwt.RegisteredClaims, now time.Time) error {
	// Check expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(now) {
		return ErrTokenExpired
	}

	// Check not before
	if claims.NotBefore != nil && claims.NotBefore.After(now) {
		return ErrTokenNotYetValid
	}

	// Check required fields
	if claims.Subject == "" {
		return ErrMissingSubject
	}

	return nil
}

// ============================================================================
// ERRORS
// ============================================================================

var (
	// ErrTokenExpired indicates the token has passed its expiration time
	ErrTokenExpired = NewTokenError("token has expired")

	// ErrTokenNotYetValid indicates the token's nbf (not before) time hasn't been reached
	ErrTokenNotYetValid = NewTokenError("token not yet valid")

	// ErrMissingSubject indicates the token has no subject claim
	ErrMissingSubject = NewTokenError("token missing subject claim")

	// ErrInvalidAudience indicates the token audience doesn't match
	ErrInvalidAudience = NewTokenError("invalid token audience")

	// ErrInvalidIssuer indicates the token issuer doesn't match
	ErrInvalidIssuer = NewTokenError("invalid token issuer")
)

// TokenError represents a token validation error
type TokenError struct {
	message string
}

func (e *TokenError) Error() string {
	return e.message
}

func NewTokenError(message string) *TokenError {
	return &TokenError{message: message}
}
