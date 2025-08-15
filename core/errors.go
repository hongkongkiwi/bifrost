// Package bifrost error handling utilities for consistent error propagation
package bifrost

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	schemas "github.com/maximhq/bifrost/core/schemas"
)

// ErrorContext provides additional context for errors
type ErrorContext struct {
	Operation string
	Provider  schemas.ModelProvider
	Model     string
	RequestID string
	UserID    string
	Timestamp time.Time
	File      string
	Line      int
	Function  string
}

// EnhancedError wraps errors with additional context
type EnhancedError struct {
	Err     error
	Context ErrorContext
	Cause   error // Root cause if this is a wrapped error
}

func (e *EnhancedError) Error() string {
	if e.Context.Provider != "" && e.Context.Model != "" {
		return fmt.Sprintf("[%s:%s] %s: %s (%s:%d)",
			e.Context.Provider, e.Context.Model, e.Context.Operation, e.Err.Error(),
			e.Context.File, e.Context.Line)
	} else if e.Context.Operation != "" {
		return fmt.Sprintf("[%s] %s (%s:%d)",
			e.Context.Operation, e.Err.Error(), e.Context.File, e.Context.Line)
	}
	return fmt.Sprintf("%s (%s:%d)", e.Err.Error(), e.Context.File, e.Context.Line)
}

func (e *EnhancedError) Unwrap() error {
	if e.Cause != nil {
		return e.Cause
	}
	return e.Err
}

// ErrorBuilder provides a fluent interface for building enhanced errors
type ErrorBuilder struct {
	ctx *ErrorContext
}

// NewErrorBuilder creates a new error builder with file location info
func NewErrorBuilder() *ErrorBuilder {
	pc, file, line, ok := runtime.Caller(1)
	var funcName string
	if ok {
		funcName = runtime.FuncForPC(pc).Name()
	}

	return &ErrorBuilder{
		ctx: &ErrorContext{
			Timestamp: time.Now(),
			File:      file,
			Line:      line,
			Function:  funcName,
		},
	}
}

func (b *ErrorBuilder) Operation(op string) *ErrorBuilder {
	b.ctx.Operation = op
	return b
}

func (b *ErrorBuilder) Provider(provider schemas.ModelProvider) *ErrorBuilder {
	b.ctx.Provider = provider
	return b
}

func (b *ErrorBuilder) Model(model string) *ErrorBuilder {
	b.ctx.Model = model
	return b
}

func (b *ErrorBuilder) RequestID(id string) *ErrorBuilder {
	b.ctx.RequestID = id
	return b
}

func (b *ErrorBuilder) UserID(id string) *ErrorBuilder {
	b.ctx.UserID = id
	return b
}

func (b *ErrorBuilder) Wrap(err error) *EnhancedError {
	enhanced := &EnhancedError{
		Err:     err,
		Context: *b.ctx,
	}

	// If the wrapped error is already enhanced, preserve the root cause
	if existingEnhanced, ok := err.(*EnhancedError); ok {
		enhanced.Cause = existingEnhanced.Cause
		if enhanced.Cause == nil {
			enhanced.Cause = existingEnhanced.Err
		}
	} else {
		enhanced.Cause = err
	}

	return enhanced
}

func (b *ErrorBuilder) Errorf(format string, args ...interface{}) *EnhancedError {
	return b.Wrap(fmt.Errorf(format, args...))
}

// Context-aware error helpers

// Context keys for error context
type contextKey string

const (
	requestIDKey contextKey = "request_id"
	userIDKey    contextKey = "user_id"
)

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// WithUserID adds a user ID to the context
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// ExtractErrorContext extracts error context from a context.Context if available
func ExtractErrorContext(ctx context.Context) ErrorContext {
	errorCtx := ErrorContext{
		Timestamp: time.Now(),
	}

	if ctx == nil {
		return errorCtx
	}

	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		errorCtx.RequestID = requestID
	}

	if userID, ok := ctx.Value(userIDKey).(string); ok {
		errorCtx.UserID = userID
	}

	return errorCtx
}

// NewContextualError creates an error with context extracted from ctx
func NewContextualError(ctx context.Context, operation string, err error) *EnhancedError {
	errorCtx := ExtractErrorContext(ctx)
	errorCtx.Operation = operation

	// Get caller info
	pc, file, line, ok := runtime.Caller(1)
	var funcName string
	if ok {
		funcName = runtime.FuncForPC(pc).Name()
	}

	errorCtx.File = file
	errorCtx.Line = line
	errorCtx.Function = funcName

	enhanced := &EnhancedError{
		Err:     err,
		Context: errorCtx,
	}

	// Preserve root cause
	if existingEnhanced, ok := err.(*EnhancedError); ok {
		enhanced.Cause = existingEnhanced.Cause
		if enhanced.Cause == nil {
			enhanced.Cause = existingEnhanced.Err
		}
	} else {
		enhanced.Cause = err
	}

	return enhanced
}

// NewContextualErrorf creates an error with context and formatted message
func NewContextualErrorf(ctx context.Context, operation string, format string, args ...interface{}) *EnhancedError {
	return NewContextualError(ctx, operation, fmt.Errorf(format, args...))
}

// Provider-specific error builders

// NewProviderError creates an error specific to a provider operation
func NewProviderError(provider schemas.ModelProvider, model, operation string, err error) *EnhancedError {
	return NewErrorBuilder().
		Provider(provider).
		Model(model).
		Operation(operation).
		Wrap(err)
}

// NewProviderErrorf creates a formatted provider error
func NewProviderErrorf(provider schemas.ModelProvider, model, operation, format string, args ...interface{}) *EnhancedError {
	return NewProviderError(provider, model, operation, fmt.Errorf(format, args...))
}

// Validation error helpers

// NewValidationError creates a validation error
func NewValidationError(field, message string) *EnhancedError {
	return NewErrorBuilder().
		Operation("validation").
		Errorf("invalid %s: %s", field, message)
}

// NewConfigurationError creates a configuration error
func NewConfigurationError(component, message string) *EnhancedError {
	return NewErrorBuilder().
		Operation("configuration").
		Errorf("configuration error in %s: %s", component, message)
}

// IsErrorType checks if an error is of a specific type
func IsErrorType(err error, errorType string) bool {
	if enhanced, ok := err.(*EnhancedError); ok {
		return enhanced.Context.Operation == errorType
	}
	return false
}

// IsProviderError checks if an error is from a specific provider
func IsProviderError(err error, provider schemas.ModelProvider) bool {
	if enhanced, ok := err.(*EnhancedError); ok {
		return enhanced.Context.Provider == provider
	}
	return false
}

// GetErrorProvider extracts the provider from an enhanced error
func GetErrorProvider(err error) schemas.ModelProvider {
	if enhanced, ok := err.(*EnhancedError); ok {
		return enhanced.Context.Provider
	}
	return ""
}

// GetErrorModel extracts the model from an enhanced error
func GetErrorModel(err error) string {
	if enhanced, ok := err.(*EnhancedError); ok {
		return enhanced.Context.Model
	}
	return ""
}

// LogError logs an error with appropriate context
func LogError(logger schemas.Logger, err error) {
	if enhanced, ok := err.(*EnhancedError); ok {
		errorMsg := fmt.Sprintf("[%s] Error in %s: %s (file: %s:%d, time: %s)",
			enhanced.Context.Operation,
			enhanced.Context.Function,
			enhanced.Err.Error(),
			enhanced.Context.File,
			enhanced.Context.Line,
			enhanced.Context.Timestamp.Format(time.RFC3339),
		)
		logger.Error(errors.New(errorMsg))

		// Log additional context if available
		var contextParts []string
		if enhanced.Context.RequestID != "" {
			contextParts = append(contextParts, fmt.Sprintf("RequestID: %s", enhanced.Context.RequestID))
		}
		if enhanced.Context.UserID != "" {
			contextParts = append(contextParts, fmt.Sprintf("UserID: %s", enhanced.Context.UserID))
		}
		if enhanced.Context.Provider != "" {
			contextParts = append(contextParts, fmt.Sprintf("Provider: %s", enhanced.Context.Provider))
		}
		if enhanced.Context.Model != "" {
			contextParts = append(contextParts, fmt.Sprintf("Model: %s", enhanced.Context.Model))
		}
		if len(contextParts) > 0 {
			logger.Debug(fmt.Sprintf("Error context: %s", strings.Join(contextParts, ", ")))
		}
	} else {
		logger.Error(err)
	}
}
