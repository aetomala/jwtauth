// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package tokens

// IssueOption configures per-call behaviour of token issuing methods.
type IssueOption func(*issueConfig)

type issueConfig struct {
	audience []string // nil means "use manager default"
}

// WithAudience overrides the manager's configured Audience for this single issuing call.
// Passing no arguments is a no-op — the manager's configured Audience is used.
// On IssueRefreshToken and IssueRefreshTokenWithClaims, the audience affects the stored
// refresh token record only, not the opaque token value itself.
func WithAudience(audience ...string) IssueOption {
	return func(c *issueConfig) {
		if len(audience) > 0 {
			c.audience = audience
		}
	}
}

// resolveAudience returns the effective audience for a call.
// Falls back to managerDefault when no WithAudience option provides a non-empty slice.
func resolveAudience(managerDefault []string, opts []IssueOption) []string {
	cfg := &issueConfig{}
	for _, o := range opts {
		o(cfg)
	}
	if len(cfg.audience) > 0 {
		return cfg.audience
	}
	return managerDefault
}

// audienceEqual reports whether two audience slices have identical contents.
func audienceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
