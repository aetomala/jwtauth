package storage

import "errors"

var (
	ErrTokenNotFound  = errors.New("refresh token not found")
	ErrTokenExpired   = errors.New("refresh token has expired")
	ErrTokenRevoked   = errors.New("refresh token has been revoked")
	ErrInvalidTokenID = errors.New("invalid token ID")
	ErrInvalidUserID  = errors.New("invalid user ID")
)
