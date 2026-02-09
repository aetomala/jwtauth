package testutil

import (
	"sync"
	"time"
)

// MockRateLimiter is a mock implementation of the RateLimiter interface for testing.
// It provides controllable behavior for testing components that depend on rate limiting.
//
// Thread-safe: Can be used with concurrent tests.
//
// Example Usage:
//
//	mockRL := testutil.NewMockRateLimiter()
//	mockRL.SetAllowResult(false) // Block all requests
//
//	middleware := middleware.NewValidator(middleware.Config{
//	    RateLimiter: mockRL,
//	})
//
//	// Verify rate limit was checked
//	Expect(mockRL.AllowCalls).To(Equal(1))
type MockRateLimiter struct {
	resetTime         time.Time
	allowError        error
	limits            map[string]*RateLimitState
	AllowArgs         []AllowCallArgs
	ResetArgs         []string
	GetStatusArgs     []string
	remainingRequests int
	AllowCalls        int
	ResetCalls        int
	GetStatusCalls    int
	mu                sync.RWMutex
	allowResult       bool
}

// AllowCallArgs captures arguments from Allow calls.
type AllowCallArgs struct {
	Identifier string
	Cost       int
}

// RateLimitState represents the rate limit state for an identifier.
type RateLimitState struct {
	ResetAt    time.Time
	Remaining  int
	TotalCalls int
	Blocked    int
	Allowed    bool
}

// RateLimitStatus represents rate limit information.
type RateLimitStatus struct {
	ResetAt   time.Time
	Limit     int
	Remaining int
}

// NewMockRateLimiter creates a new MockRateLimiter.
// By default, allows all requests with 100 remaining.
func NewMockRateLimiter() *MockRateLimiter {
	return &MockRateLimiter{
		allowResult:       true,
		remainingRequests: 100,
		resetTime:         time.Now().Add(1 * time.Hour),
		limits:            make(map[string]*RateLimitState),
	}
}

// Allow checks if a request should be allowed.
// Tracks call count and arguments, returns configured result/error.
func (m *MockRateLimiter) Allow(identifier string, cost int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.AllowCalls++
	m.AllowArgs = append(m.AllowArgs, AllowCallArgs{
		Identifier: identifier,
		Cost:       cost,
	})

	if m.allowError != nil {
		return false, m.allowError
	}

	// Track per-identifier state
	state, exists := m.limits[identifier]
	if !exists {
		state = &RateLimitState{
			Allowed:    true,
			Remaining:  m.remainingRequests,
			ResetAt:    m.resetTime,
			TotalCalls: 0,
			Blocked:    0,
		}
		m.limits[identifier] = state
	}

	state.TotalCalls++

	// Use configured global result
	allowed := m.allowResult

	if allowed {
		state.Allowed = true
		if state.Remaining > 0 {
			state.Remaining -= cost
		}
	} else {
		state.Allowed = false
		state.Blocked++
	}

	return allowed, nil
}

// Reset resets the rate limit for an identifier.
// Tracks call count and arguments.
func (m *MockRateLimiter) Reset(identifier string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ResetCalls++
	m.ResetArgs = append(m.ResetArgs, identifier)

	if state, exists := m.limits[identifier]; exists {
		state.Remaining = m.remainingRequests
		state.ResetAt = time.Now().Add(1 * time.Hour)
		state.Blocked = 0
	}

	return nil
}

// GetStatus returns the rate limit status for an identifier.
// Tracks call count and arguments.
func (m *MockRateLimiter) GetStatus(identifier string) (*RateLimitStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GetStatusCalls++
	m.GetStatusArgs = append(m.GetStatusArgs, identifier)

	state, exists := m.limits[identifier]
	if !exists {
		// Return default status
		return &RateLimitStatus{
			Limit:     100,
			Remaining: m.remainingRequests,
			ResetAt:   m.resetTime,
		}, nil
	}

	return &RateLimitStatus{
		Limit:     100,
		Remaining: state.Remaining,
		ResetAt:   state.ResetAt,
	}, nil
}

// ===== Behavior Control Methods =====

// SetAllowResult configures what Allow() returns.
func (m *MockRateLimiter) SetAllowResult(allowed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowResult = allowed
}

// SetAllowError configures Allow() to return an error.
func (m *MockRateLimiter) SetAllowError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowError = err
}

// SetRemainingRequests sets the number of remaining requests.
func (m *MockRateLimiter) SetRemainingRequests(remaining int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.remainingRequests = remaining
}

// SetResetTime sets when the rate limit resets.
func (m *MockRateLimiter) SetResetTime(resetTime time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resetTime = resetTime
}

// SetLimitForIdentifier sets specific rate limit state for an identifier.
func (m *MockRateLimiter) SetLimitForIdentifier(identifier string, remaining int, resetAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.limits[identifier] = &RateLimitState{
		Allowed:    remaining > 0,
		Remaining:  remaining,
		ResetAt:    resetAt,
		TotalCalls: 0,
		Blocked:    0,
	}
}

// BlockIdentifier configures the rate limiter to block a specific identifier.
func (m *MockRateLimiter) BlockIdentifier(identifier string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, exists := m.limits[identifier]
	if !exists {
		state = &RateLimitState{
			Allowed:    false,
			Remaining:  0,
			ResetAt:    m.resetTime,
			TotalCalls: 0,
			Blocked:    0,
		}
		m.limits[identifier] = state
	}

	state.Remaining = 0
	state.Allowed = false
}

// UnblockIdentifier configures the rate limiter to allow a specific identifier.
func (m *MockRateLimiter) UnblockIdentifier(identifier string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, exists := m.limits[identifier]
	if !exists {
		state = &RateLimitState{
			Allowed:    true,
			Remaining:  m.remainingRequests,
			ResetAt:    m.resetTime,
			TotalCalls: 0,
			Blocked:    0,
		}
		m.limits[identifier] = state
	}

	state.Remaining = m.remainingRequests
	state.Allowed = true
}

// ===== Query Methods =====

// GetCallCount returns the number of times a specific method was called.
func (m *MockRateLimiter) GetCallCount(method string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch method {
	case "Allow":
		return m.AllowCalls
	case "Reset":
		return m.ResetCalls
	case "GetStatus":
		return m.GetStatusCalls
	default:
		return 0
	}
}

// WasIdentifierChecked checks if Allow was called for a specific identifier.
func (m *MockRateLimiter) WasIdentifierChecked(identifier string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, args := range m.AllowArgs {
		if args.Identifier == identifier {
			return true
		}
	}
	return false
}

// GetIdentifierCallCount returns how many times Allow was called for an identifier.
func (m *MockRateLimiter) GetIdentifierCallCount(identifier string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, args := range m.AllowArgs {
		if args.Identifier == identifier {
			count++
		}
	}
	return count
}

// GetTotalCost returns the total cost of all Allow calls for an identifier.
func (m *MockRateLimiter) GetTotalCost(identifier string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := 0
	for _, args := range m.AllowArgs {
		if args.Identifier == identifier {
			total += args.Cost
		}
	}
	return total
}

// GetBlockedCount returns how many times an identifier was blocked.
func (m *MockRateLimiter) GetBlockedCount(identifier string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if state, exists := m.limits[identifier]; exists {
		return state.Blocked
	}
	return 0
}

// GetRemainingForIdentifier returns remaining requests for an identifier.
func (m *MockRateLimiter) GetRemainingForIdentifier(identifier string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if state, exists := m.limits[identifier]; exists {
		return state.Remaining
	}
	return m.remainingRequests
}

// IsIdentifierBlocked checks if an identifier is currently blocked.
func (m *MockRateLimiter) IsIdentifierBlocked(identifier string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if state, exists := m.limits[identifier]; exists {
		return state.Remaining <= 0 || !state.Allowed
	}
	return false
}

// GetAllIdentifiers returns all identifiers that have been checked.
func (m *MockRateLimiter) GetAllIdentifiers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	identifiers := make(map[string]bool)
	for _, args := range m.AllowArgs {
		identifiers[args.Identifier] = true
	}

	result := make([]string, 0, len(identifiers))
	for id := range identifiers {
		result = append(result, id)
	}
	return result
}

// ===== Reset Methods =====

// ResetCounters resets all call counters and arguments.
func (m *MockRateLimiter) ResetCounters() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.AllowCalls = 0
	m.ResetCalls = 0
	m.GetStatusCalls = 0

	m.AllowArgs = nil
	m.ResetArgs = nil
	m.GetStatusArgs = nil
}

// ResetState resets all rate limit state for all identifiers.
func (m *MockRateLimiter) ResetState() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.limits = make(map[string]*RateLimitState)
}

// ResetAll resets counters, state, and errors.
func (m *MockRateLimiter) ResetAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.AllowCalls = 0
	m.ResetCalls = 0
	m.GetStatusCalls = 0

	m.AllowArgs = nil
	m.ResetArgs = nil
	m.GetStatusArgs = nil

	m.limits = make(map[string]*RateLimitState)

	m.allowError = nil
	m.allowResult = true
	m.remainingRequests = 100
	m.resetTime = time.Now().Add(1 * time.Hour)
}

// ResetErrors resets all configured errors.
func (m *MockRateLimiter) ResetErrors() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.allowError = nil
}

// ===== Helper Methods for Testing Rate Limiting Scenarios =====

// SimulateRateLimitExceeded simulates a rate limit being exceeded.
func (m *MockRateLimiter) SimulateRateLimitExceeded(identifier string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.limits[identifier] = &RateLimitState{
		Allowed:    false,
		Remaining:  0,
		ResetAt:    time.Now().Add(1 * time.Hour),
		TotalCalls: 100,
		Blocked:    1,
	}
}

// SimulateRateLimitReset simulates a rate limit being reset.
func (m *MockRateLimiter) SimulateRateLimitReset(identifier string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.limits[identifier] = &RateLimitState{
		Allowed:    true,
		Remaining:  100,
		ResetAt:    time.Now().Add(1 * time.Hour),
		TotalCalls: 0,
		Blocked:    0,
	}
}

// SimulateNearLimit simulates being near the rate limit.
func (m *MockRateLimiter) SimulateNearLimit(identifier string, remaining int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.limits[identifier] = &RateLimitState{
		Allowed:    remaining > 0,
		Remaining:  remaining,
		ResetAt:    time.Now().Add(1 * time.Hour),
		TotalCalls: 100 - remaining,
		Blocked:    0,
	}
}

// ===== Mock-Specific Errors =====

var (
	// ErrMockRateLimitExceeded is returned when rate limit is exceeded.
	ErrMockRateLimitExceeded = NewMockError("rate limit exceeded")

	// ErrMockInvalidIdentifier is returned for invalid identifiers.
	ErrMockInvalidIdentifier = NewMockError("invalid identifier")
)
