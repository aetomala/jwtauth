// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"strings"

	"github.com/aetomala/jwtauth/internal/tokenref"
)

// scrubbedError is a RefreshStore error whose text has the refresh token
// replaced by its tokenref digest. Unwrap returns the original error so
// errors.Is and errors.As keep working — callers that print the unwrapped
// cause see its original text. It is immutable and safe for concurrent use.
type scrubbedError struct {
	err error  // Original store error
	msg string // err.Error() with every occurrence of the token replaced
}

// Error returns the scrubbed error text.
func (e *scrubbedError) Error() string { return e.msg }

// Unwrap returns the original store error.
func (e *scrubbedError) Unwrap() error { return e.err }

// scrubStoreError returns err with every occurrence of token in its text
// replaced by tokenref.Ref(token), so a RefreshStore that violates its contract
// by embedding the token in an error cannot leak it through logs, spans, or
// returned errors. It returns err unchanged if err is nil, token is empty, or
// the text does not contain the token — so contract-compliant errors keep their
// identity. Only exact occurrences are replaced — see ADR-012.
func scrubStoreError(err error, token string) error {
	if err == nil || token == "" {
		return err
	}
	text := err.Error()
	if !strings.Contains(text, token) {
		return err
	}
	return &scrubbedError{err: err, msg: tokenref.Scrub(text, token)}
}
