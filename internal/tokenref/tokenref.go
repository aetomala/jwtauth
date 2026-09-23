// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package tokenref

import (
	"crypto/sha256"
	"encoding/hex"
)

// refLen is the number of hex characters kept from the SHA-256 digest.
const refLen = 16

// Ref returns a non-reversible reference to a refresh token for use in logs and traces.
// It returns the first 16 hex characters of the SHA-256 digest of token, or "" if token is "".
func Ref(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:refLen]
}
