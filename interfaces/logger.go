package interfaces

// LogLevel represents the severity level of a log message
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// Logger defines the interface for logging operations
type Logger interface {
	// Debug logs a debug level message
	Debug(msg string)

	// Info logs an info level message
	Info(msg string)

	// Warn logs a warning level message
	Warn(msg string)

	// Error logs an error level message
	Error(err error)

	// Formatted variants for structured logging
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})

	// Level management
	GetLevel() LogLevel
	SetLevel(level LogLevel)
}
