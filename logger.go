package bifrost

import (
	"fmt"
	"os"
	"time"

	"github.com/maximhq/bifrost/interfaces"
)

// DefaultLogger implements the Logger interface with stdout printing
type DefaultLogger struct {
	level interfaces.LogLevel
}

// Ensure DefaultLogger implements interfaces.Logger
var _ interfaces.Logger = (*DefaultLogger)(nil)

// NewDefaultLogger creates a new DefaultLogger instance
func NewDefaultLogger(level interfaces.LogLevel) *DefaultLogger {
	return &DefaultLogger{
		level: level,
	}
}

// formatMessage formats the log message with timestamp and level
func (logger *DefaultLogger) formatMessage(level interfaces.LogLevel, msg string, err error) string {
	timestamp := time.Now().Format(time.RFC3339)
	baseMsg := fmt.Sprintf("[BIFROST-%s] %s: %s", timestamp, level, msg)
	if err != nil {
		return fmt.Sprintf("%s (error: %v)", baseMsg, err)
	}
	return baseMsg
}

// Debug logs a debug level message
func (logger *DefaultLogger) Debug(msg string) {
	if logger.level == interfaces.LogLevelDebug {
		fmt.Fprintln(os.Stdout, logger.formatMessage(interfaces.LogLevelDebug, msg, nil))
	}
}

// Info logs an info level message
func (logger *DefaultLogger) Info(msg string) {
	if logger.level == interfaces.LogLevelDebug || logger.level == interfaces.LogLevelInfo {
		fmt.Fprintln(os.Stdout, logger.formatMessage(interfaces.LogLevelInfo, msg, nil))
	}
}

// Warn logs a warning level message
func (logger *DefaultLogger) Warn(msg string) {
	if logger.level == interfaces.LogLevelDebug || logger.level == interfaces.LogLevelInfo || logger.level == interfaces.LogLevelWarn {
		fmt.Fprintln(os.Stdout, logger.formatMessage(interfaces.LogLevelWarn, msg, nil))
	}
}

// Error logs an error level message
func (logger *DefaultLogger) Error(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, logger.formatMessage(interfaces.LogLevelError, err.Error(), err))
}

// Debugf logs a formatted debug level message
func (logger *DefaultLogger) Debugf(format string, args ...interface{}) {
	logger.Debug(fmt.Sprintf(format, args...))
}

// Infof logs a formatted info level message
func (logger *DefaultLogger) Infof(format string, args ...interface{}) {
	logger.Info(fmt.Sprintf(format, args...))
}

// Warnf logs a formatted warning level message
func (logger *DefaultLogger) Warnf(format string, args ...interface{}) {
	logger.Warn(fmt.Sprintf(format, args...))
}

// Errorf logs a formatted error level message
func (logger *DefaultLogger) Errorf(format string, args ...interface{}) {
	logger.Error(fmt.Errorf(format, args...))
}

// GetLevel returns the current logging level
func (logger *DefaultLogger) GetLevel() interfaces.LogLevel {
	return logger.level
}

// SetLevel sets the logging level
func (logger *DefaultLogger) SetLevel(level interfaces.LogLevel) {
	logger.level = level
}
