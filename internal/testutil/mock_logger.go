package testutil

import (
	"sync"

	"github.com/aetomala/jwtauth/pkg/logging"
)

// Ensure MockLogger implements logging.Logger at compile time
var _ logging.Logger = (*MockLogger)(nil)

// MockLogger implements the logging.Logger interface for testing.
// It records all log calls in memory for verification in tests.
//
// Thread safe: Can be used with concurrent tests.
//
// Example Usage:
//
// mockLogger := testutil.NewMockLogger()
//
//	manager := keymanager.NewManager(keymanager.ManagerConfig{
//			Logger: mockLogger,
//	})
//
// manager.Start(ctx)
//
// // Verify logs
//
//		if !mockLogger.HasLog("info", "key manager started"){
//			t.Error("Expected rotation log with keyId field")
//	}
//
// // Check log fields
//
//	if !mockLogger.HasLogWithField("info", "key rotation successful", "keyID") {
//			t.Error("Expected rotation log with keyID field")
//	}
type MockLogger struct {
	mu     sync.RWMutex
	logs   []LogEntry
	enable bool
}

// LogEntry represents a single log entry captured by MockLogger.
type LogEntry struct {
	Level   string                 // "info","warn","error"
	Message string                 // Log message
	Fields  map[string]interface{} // Structured fields (key-value pairs)
}

// NewMockLogger create a new MockLogger instance.
func NewMockLogger() *MockLogger {
	return &MockLogger{
		logs:   make([]LogEntry, 0),
		enable: true,
	}
}

// Info records an info-level log entry
func (m *MockLogger) Info(msg string, keysAndValues ...interface{}) {
	if !m.enable {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, LogEntry{
		Level:   "info",
		Message: msg,
		Fields:  m.parseFields(keysAndValues),
	})
}

// Warn records an warn-level log entry
func (m *MockLogger) Warn(msg string, keysAndValues ...interface{}) {
	if !m.enable {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, LogEntry{
		Level:   "warn",
		Message: msg,
		Fields:  m.parseFields(keysAndValues),
	})
}

// Error records an error-level log entry
func (m *MockLogger) Error(msg string, keysAndValues ...interface{}) {
	if !m.enable {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, LogEntry{
		Level:   "error",
		Message: msg,
		Fields:  m.parseFields(keysAndValues),
	})
}

// parseFields converts alernative key-value pairs into a map
func (m *MockLogger) parseFields(keysAndValues []interface{}) map[string]interface{} {
	fields := make(map[string]interface{})
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			key, ok := keysAndValues[i].(string)
			if !ok {
				continue // Skip non-string keys
			}
			value := keysAndValues[i+1]
			fields[key] = value
		}
	}
	return fields
}

// GetLogs returns a copy of all log entries.
// Safe for concurrent user.
func (m *MockLogger) GetLogs() []LogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return copy to prevent race conditions
	logs := make([]LogEntry, len(m.logs))
	copy(logs, m.logs)
	return logs
}

// Clear removes all recorded log entries.
// Useful for clearing logs between test phases.
func (m *MockLogger) Clear() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.logs = make([]LogEntry, 0)
}

// HasLog checks if a log with the given level and message exists.
//
// Example:
//
//	if mockLogger.HasLog("info", "key rotation successful") {
//	    // Test passes
//	}
func (m *MockLogger) HasLog(level, message string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, log := range m.logs {
		if log.Level == level && log.Message == message {
			return true
		}
	}
	return false
}

// HasLogWithField checks if a log with the given level, message and field key exists.
//
// Example:
//
//	if mockLogger.HasLogWithField("info", "key rotation successfull", "keyID"){
//			// Test passes - log had keyID field
//	}
func (m *MockLogger) HasLogWithField(level string, message string, fieldKey string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, log := range m.logs {
		if log.Level == level && log.Message == message {
			if _, exists := log.Fields[fieldKey]; exists {
				return true
			}
		}
	}
	return false
}

// GetLogWithField returns the first log matching level, message, and having the specified field.
// Returns nil if not found.
//
// Example:
//
//	log := mockLogger.GetLogWithField("info", "key rotation successful", "duration")
//	if log != nil {
//	    duration := log.Fields["duration"]
//	    // Verify duration value
//	}
func (m *MockLogger) GetLogWithField(level, message, fieldKey string) *LogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, log := range m.logs {
		if log.Level == level && log.Message == message {
			if _, exists := log.Fields[fieldKey]; exists {
				// Return copy to prevent race conditions
				logCopy := log
				return &logCopy
			}
		}
	}
	return nil
}

// CountLogs returns the number of logs at the given level.
//
// Example:
//
//	errorCount := mockLogger.CountLogs("error")
//	if errorCount > 0 {
//	    t.Errorf("Expected no errors, got %d", errorCount)
//	}
func (m *MockLogger) CountLogs(level string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, log := range m.logs {
		if log.Level == level {
			count++
		}
	}
	return count
}

// GetLogsByLevel returns all logs at the given level.
//
// Example:
//
//	warnLogs := mockLogger.GetLogsByLevel("warn")
//	for _, log := range warnLogs {
//	    fmt.Printf("Warning: %s\n", log.Message)
//	}
func (m *MockLogger) GetLogsByLevel(level string) []LogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	logs := make([]LogEntry, 0)
	for _, log := range m.logs {
		if log.Level == level {
			logs = append(logs, log)
		}
	}
	return logs
}

// Disable stops the MockLogger from recording logs.
// Useful for focusing on specific test phases.
func (m *MockLogger) Disable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enable = false
}

// Enable resumes log recording.
func (m *MockLogger) Enable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enable = true
}

// IsEnabled returns whether the logger is currently recording logs.
func (m *MockLogger) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enable
}
