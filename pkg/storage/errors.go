// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package storage

import "errors"

var (
	ErrTokenNotFound    = errors.New("refresh token not found")
	ErrTokenExpired     = errors.New("refresh token has expired")
	ErrTokenRevoked     = errors.New("refresh token has been revoked")
	ErrInvalidTokenID   = errors.New("invalid token ID")
	ErrInvalidUserID    = errors.New("invalid user ID")
	ErrInvalidAudience  = errors.New("invalid audience: must not be empty")
)
