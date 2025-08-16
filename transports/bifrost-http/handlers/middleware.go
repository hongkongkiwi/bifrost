// Package handlers provides HTTP request handlers and middleware for the Bifrost HTTP transport.
package handlers

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail contains detailed error information
type ErrorDetail struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	RequestID string                 `json:"request_id"`
	Timestamp string                 `json:"timestamp"`
}

// RequestIDKey is the context key for request ID
const RequestIDKey = "request_id"

// ErrorMiddleware provides centralized error handling and recovery
func ErrorMiddleware(next fasthttp.RequestHandler, logger schemas.Logger) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		// Generate request ID
		requestID := uuid.New().String()
		ctx.SetUserValue(RequestIDKey, requestID)
		
		// Add request ID to response headers
		ctx.Response.Header.Set("X-Request-ID", requestID)
		
		// Recover from panics
		defer func() {
			if r := recover(); r != nil {
				logger.Error(fmt.Errorf("panic recovered: %v\nStack: %s", r, debug.Stack()))
				
				SendStandardError(ctx, fasthttp.StatusInternalServerError, 
					"internal_server_error", 
					"An unexpected error occurred", 
					map[string]interface{}{
						"panic": fmt.Sprintf("%v", r),
					}, logger)
			}
		}()
		
		// Call the next handler
		next(ctx)
	}
}

// SendStandardError sends a standardized error response
func SendStandardError(ctx *fasthttp.RequestCtx, statusCode int, code, message string, details map[string]interface{}, logger schemas.Logger) {
	requestID := ""
	if id := ctx.UserValue(RequestIDKey); id != nil {
		requestID = id.(string)
	}
	
	errorResp := ErrorResponse{
		Error: ErrorDetail{
			Code:      code,
			Message:   message,
			Details:   details,
			RequestID: requestID,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
	
	ctx.SetStatusCode(statusCode)
	ctx.SetContentType("application/json")
	
	if err := json.NewEncoder(ctx).Encode(errorResp); err != nil {
		logger.Error(fmt.Errorf("failed to encode error response: %w", err))
		ctx.SetBodyString(`{"error":{"code":"encoding_error","message":"Failed to encode error response"}}`)
	}
}

// ConvertBifrostError converts a BifrostError to standardized error response
func ConvertBifrostError(ctx *fasthttp.RequestCtx, bifrostErr *schemas.BifrostError, logger schemas.Logger) {
	statusCode := fasthttp.StatusInternalServerError
	if bifrostErr.StatusCode != nil {
		statusCode = *bifrostErr.StatusCode
	} else if !bifrostErr.IsBifrostError {
		statusCode = fasthttp.StatusBadRequest
	}
	
	code := "provider_error"
	if bifrostErr.Type != nil {
		code = *bifrostErr.Type
	} else if bifrostErr.IsBifrostError {
		code = "bifrost_error"
	}
	
	details := make(map[string]interface{})
	if bifrostErr.Provider != "" {
		details["provider"] = bifrostErr.Provider
	}
	if bifrostErr.EventID != nil {
		details["event_id"] = *bifrostErr.EventID
	}
	if bifrostErr.Error.Type != nil {
		details["error_type"] = *bifrostErr.Error.Type
	}
	if bifrostErr.Error.Error != nil {
		details["original_error"] = bifrostErr.Error.Error.Error()
	}
	
	SendStandardError(ctx, statusCode, code, bifrostErr.Error.Message, details, logger)
}

// RetryMiddleware adds retry capability with exponential backoff
func RetryMiddleware(maxRetries int, initialDelay time.Duration) func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			var lastErr error
			delay := initialDelay
			
			for attempt := 0; attempt <= maxRetries; attempt++ {
				// Clone the context for retry
				if attempt > 0 {
					time.Sleep(delay)
					delay *= 2 // Exponential backoff
				}
				
				// Try the request
				next(ctx)
				
				// Check if we should retry
				statusCode := ctx.Response.StatusCode()
				if statusCode < 500 {
					// Success or client error - don't retry
					return
				}
				
				lastErr = fmt.Errorf("request failed with status %d", statusCode)
			}
			
			// All retries failed
			if lastErr != nil {
				ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
				ctx.SetBodyString(fmt.Sprintf(`{"error":{"code":"max_retries_exceeded","message":"Request failed after %d retries"}}`, maxRetries))
			}
		}
	}
}

// LoggingMiddleware logs all requests and responses
func LoggingMiddleware(logger schemas.Logger) func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			start := time.Now()
			
			// Log request
			logger.Debug(fmt.Sprintf("[%s] %s %s", 
				ctx.UserValue(RequestIDKey),
				ctx.Method(),
				ctx.RequestURI()))
			
			// Process request
			next(ctx)
			
			// Log response
			duration := time.Since(start)
			logger.Debug(fmt.Sprintf("[%s] %d %s (%v)", 
				ctx.UserValue(RequestIDKey),
				ctx.Response.StatusCode(),
				ctx.RequestURI(),
				duration))
			
			// Log errors
			if ctx.Response.StatusCode() >= 400 {
				logger.Warn(fmt.Sprintf("[%s] Error response %d for %s %s", 
					ctx.UserValue(RequestIDKey),
					ctx.Response.StatusCode(),
					ctx.Method(),
					ctx.RequestURI()))
			}
		}
	}
}

// RateLimitMiddleware implements basic rate limiting
func RateLimitMiddleware(requestsPerSecond int) func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	// Simple token bucket implementation
	ticker := time.NewTicker(time.Second / time.Duration(requestsPerSecond))
	tokens := make(chan struct{}, requestsPerSecond)
	
	// Fill initial tokens
	for i := 0; i < requestsPerSecond; i++ {
		tokens <- struct{}{}
	}
	
	// Refill tokens
	go func() {
		for range ticker.C {
			select {
			case tokens <- struct{}{}:
			default:
				// Bucket full, skip
			}
		}
	}()
	
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			select {
			case <-tokens:
				// Token acquired, process request
				next(ctx)
			default:
				// No tokens available
				ctx.SetStatusCode(fasthttp.StatusTooManyRequests)
				ctx.SetBodyString(`{"error":{"code":"rate_limit_exceeded","message":"Too many requests"}}`)
			}
		}
	}
}

// CORSMiddleware handles CORS headers
func CORSMiddleware(allowedOrigins []string) func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			origin := string(ctx.Request.Header.Peek("Origin"))
			
			// Check if origin is allowed
			if IsOriginAllowed(origin, allowedOrigins) {
				ctx.Response.Header.Set("Access-Control-Allow-Origin", origin)
				ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
				ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
				ctx.Response.Header.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
				ctx.Response.Header.Set("Access-Control-Max-Age", "86400")
			}
			
			// Handle preflight requests
			if string(ctx.Method()) == "OPTIONS" {
				ctx.SetStatusCode(fasthttp.StatusNoContent)
				return
			}
			
			next(ctx)
		}
	}
}