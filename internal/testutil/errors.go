package testutil

import "fmt"

// MockError represents an error that occurs in mock implementations.
// It provides a simple way to create identifiable errors for testing.
type MockError struct {
	message string
}

// Error implements the error interface.
func (e *MockError) Error() string {
	return e.message
}

// NewMockError creates a new MockError with the given message.
func NewMockError(message string) *MockError {
	return &MockError{message: message}
}

// IsMockError checks if an error is a MockError.
func IsMockError(err error) bool {
	_, ok := err.(*MockError)
	return ok
}

// MockErrorWithContext wraps a MockError with additional context.
type MockErrorWithContext struct {
	err     error
	context string
}

// Error implements the error interface.
func (e *MockErrorWithContext) Error() string {
	return fmt.Sprintf("%s: %v", e.context, e.err)
}

// Unwrap implements the unwrap interface for error chains.
func (e *MockErrorWithContext) Unwrap() error {
	return e.err
}

// WrapMockError wraps an error with additional context.
func WrapMockError(err error, context string) error {
	if err == nil {
		return nil
	}
	return &MockErrorWithContext{
		err:     err,
		context: context,
	}
}
