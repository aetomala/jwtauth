package ratelimit

import (
	"time"
)

// RateLimiter defines the interface for rate limiting operations.
//
// This interface ensures:
//   - Compile-time verification that implementations are complete
//   - Clear contract for rate limiting
//   - Easy mocking for testing
//   - Automatic mock generation via mockgen
//
// Implementations might include:
//   - RedisRateLimiter: Redis-backed distributed rate limiting
//   - TokenBucketLimiter: Token bucket algorithm
//   - SlidingWindowLimiter: Sliding window algorithm
//   - MockRateLimiter (testutil): Auto-generated testing implementation
type RateLimiter interface {
	// Allow checks if a request should be allowed.
	//
	// The identifier is typically:
	//   - User ID (per-user limits)
	//   - IP address (per-IP limits)
	//   - API key (per-client limits)
	//
	// The cost represents resource consumption:
	//   - 1 for normal requests
	//   - Higher for expensive operations
	//
	// Args:
	//   - identifier: The entity being rate limited (user, IP, etc.)
	//   - cost: Request cost (typically 1)
	//
	// Returns:
	//   - allowed: Whether the request should be allowed
	//   - error: If rate limit check fails
	Allow(identifier string, cost int) (bool, error)

	// Reset resets the rate limit for an identifier.
	//
	// Use cases:
	//   - Admin override
	//   - Testing
	//   - User upgrade to higher tier
	//
	// Args:
	//   - identifier: The entity to reset
	//
	// Returns:
	//   - error: If reset fails
	Reset(identifier string) error

	// GetStatus returns the current rate limit status for an identifier.
	//
	// Useful for:
	//   - Including rate limit info in responses
	//   - Displaying to users
	//   - Monitoring
	//
	// Args:
	//   - identifier: The entity to check
	//
	// Returns:
	//   - status: Current rate limit information
	//   - error: If status check fails
	GetStatus(identifier string) (*RateLimitStatus, error)
}

// RateLimitStatus represents rate limit information for an identifier.
type RateLimitStatus struct {
	// Limit is the maximum number of requests allowed
	Limit int

	// Remaining is the number of requests remaining in the current window
	Remaining int

	// ResetAt is when the rate limit window resets
	ResetAt time.Time
}
