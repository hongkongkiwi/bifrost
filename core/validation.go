// Package bifrost validation utilities for input sanitization and validation
package bifrost

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// InputValidator provides comprehensive input validation for Bifrost
type InputValidator struct{}

// NewInputValidator creates a new input validator instance
func NewInputValidator() *InputValidator {
	return &InputValidator{}
}

var (
	// Regex patterns for validation
	modelNamePattern    = regexp.MustCompile(`^[a-zA-Z0-9\-_./:]+$`)
	providerNamePattern = regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)
	alphanumericPattern = regexp.MustCompile(`^[a-zA-Z0-9\-_\.]+$`)

	// Dangerous patterns to reject
	sqlInjectionPattern     = regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|exec|script)`)
	commandInjectionPattern = regexp.MustCompile(`[;&|]`)

	// Maximum lengths for different input types
	maxModelNameLength = 256
	maxURLLength       = 2048
	maxHeaderLength    = 8192
	maxConfigLength    = 65536
)

// ValidateModelName validates AI model names
func (v *InputValidator) ValidateModelName(modelName string) error {
	if modelName == "" {
		return fmt.Errorf("model name cannot be empty")
	}

	if len(modelName) > maxModelNameLength {
		return fmt.Errorf("model name too long: %d characters (max %d)", len(modelName), maxModelNameLength)
	}

	// Check for dangerous characters and patterns
	if commandInjectionPattern.MatchString(modelName) {
		return fmt.Errorf("model name contains invalid characters")
	}

	if sqlInjectionPattern.MatchString(modelName) {
		return fmt.Errorf("model name contains suspicious patterns")
	}

	// Ensure model name follows expected pattern
	if !modelNamePattern.MatchString(modelName) {
		return fmt.Errorf("model name contains invalid characters: must match [a-zA-Z0-9\\-_./:]+")
	}

	return nil
}

// ValidateProviderName validates provider names
func (v *InputValidator) ValidateProviderName(providerName string) error {
	if providerName == "" {
		return fmt.Errorf("provider name cannot be empty")
	}

	if len(providerName) > 64 {
		return fmt.Errorf("provider name too long: %d characters (max 64)", len(providerName))
	}

	if !providerNamePattern.MatchString(providerName) {
		return fmt.Errorf("provider name contains invalid characters: must match [a-zA-Z0-9\\-_]+")
	}

	return nil
}

// ValidateURL validates and sanitizes URLs
func (v *InputValidator) ValidateURL(inputURL string) (string, error) {
	if inputURL == "" {
		return "", fmt.Errorf("URL cannot be empty")
	}

	if len(inputURL) > maxURLLength {
		return "", fmt.Errorf("URL too long: %d characters (max %d)", len(inputURL), maxURLLength)
	}

	// Parse and validate URL structure
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %v", err)
	}

	// Ensure scheme is HTTP or HTTPS
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("URL scheme must be http or https, got: %s", parsedURL.Scheme)
	}

	// Validate hostname
	if parsedURL.Host == "" {
		return "", fmt.Errorf("URL must have a valid hostname")
	}

	// Check for suspicious patterns in URL
	if sqlInjectionPattern.MatchString(inputURL) {
		return "", fmt.Errorf("URL contains suspicious patterns")
	}

	// Return cleaned URL
	return parsedURL.String(), nil
}

// ValidateAPIKey validates API key format and characteristics
func (v *InputValidator) ValidateAPIKey(apiKey string) error {
	if apiKey == "" {
		return fmt.Errorf("API key cannot be empty")
	}

	// Check length constraints
	if len(apiKey) < 10 {
		return fmt.Errorf("API key too short: %d characters (minimum 10)", len(apiKey))
	}

	if len(apiKey) > 512 {
		return fmt.Errorf("API key too long: %d characters (max 512)", len(apiKey))
	}

	// Check for suspicious patterns
	if commandInjectionPattern.MatchString(apiKey) {
		return fmt.Errorf("API key contains invalid characters")
	}

	// Ensure key contains only printable ASCII characters
	for _, r := range apiKey {
		if !unicode.IsPrint(r) || r > 126 {
			return fmt.Errorf("API key contains non-printable or non-ASCII characters")
		}
	}

	return nil
}

// ValidateHTTPHeader validates HTTP header names and values
func (v *InputValidator) ValidateHTTPHeader(name, value string) error {
	if name == "" {
		return fmt.Errorf("header name cannot be empty")
	}

	if value == "" {
		return fmt.Errorf("header value cannot be empty")
	}

	if len(name) > 256 {
		return fmt.Errorf("header name too long: %d characters (max 256)", len(name))
	}

	if len(value) > maxHeaderLength {
		return fmt.Errorf("header value too long: %d characters (max %d)", len(value), maxHeaderLength)
	}

	// Validate header name format (RFC 7230)
	for _, r := range name {
		if !isValidHeaderNameChar(r) {
			return fmt.Errorf("header name contains invalid character: %c", r)
		}
	}

	// Check for dangerous patterns in header value
	if strings.Contains(value, "\n") || strings.Contains(value, "\r") {
		return fmt.Errorf("header value contains line breaks")
	}

	if commandInjectionPattern.MatchString(value) {
		return fmt.Errorf("header value contains suspicious characters")
	}

	return nil
}

// ValidateJSONInput validates JSON configuration inputs
func (v *InputValidator) ValidateJSONInput(jsonStr string) error {
	if len(jsonStr) > maxConfigLength {
		return fmt.Errorf("JSON input too large: %d bytes (max %d)", len(jsonStr), maxConfigLength)
	}

	// Check for dangerous patterns
	if sqlInjectionPattern.MatchString(jsonStr) {
		return fmt.Errorf("JSON input contains suspicious patterns")
	}

	if commandInjectionPattern.MatchString(jsonStr) {
		return fmt.Errorf("JSON input contains invalid characters")
	}

	return nil
}

// SanitizeString removes potentially dangerous characters from string inputs
func (v *InputValidator) SanitizeString(input string) string {
	// Remove control characters except tab, newline, and carriage return
	result := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return -1 // Remove character
		}
		return r
	}, input)

	// Trim whitespace
	result = strings.TrimSpace(result)

	return result
}

// ValidateTimeout validates timeout values
func (v *InputValidator) ValidateTimeout(timeout int) error {
	if timeout < 0 {
		return fmt.Errorf("timeout cannot be negative: %d", timeout)
	}

	if timeout > 3600 { // Max 1 hour
		return fmt.Errorf("timeout too large: %d seconds (max 3600)", timeout)
	}

	return nil
}

// ValidateRetryCount validates retry count values
func (v *InputValidator) ValidateRetryCount(retries int) error {
	if retries < 0 {
		return fmt.Errorf("retry count cannot be negative: %d", retries)
	}

	if retries > 10 {
		return fmt.Errorf("retry count too large: %d (max 10)", retries)
	}

	return nil
}

// ValidateConcurrency validates concurrency configuration
func (v *InputValidator) ValidateConcurrency(concurrency int) error {
	if concurrency <= 0 {
		return fmt.Errorf("concurrency must be positive: %d", concurrency)
	}

	if concurrency > 1000 {
		return fmt.Errorf("concurrency too large: %d (max 1000)", concurrency)
	}

	return nil
}

// ValidateBufferSize validates buffer size configuration
func (v *InputValidator) ValidateBufferSize(bufferSize int) error {
	if bufferSize < 0 {
		return fmt.Errorf("buffer size cannot be negative: %d", bufferSize)
	}

	if bufferSize > 100000 {
		return fmt.Errorf("buffer size too large: %d (max 100000)", bufferSize)
	}

	return nil
}

// isValidHeaderNameChar checks if a rune is valid for HTTP header names
func isValidHeaderNameChar(r rune) bool {
	// Based on RFC 7230 section 3.2 - token characters
	// token = 1*tchar
	// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
	return (r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '!' || r == '#' || r == '$' || r == '%' || r == '&' ||
		r == '\'' || r == '*' || r == '+' || r == '-' || r == '.' ||
		r == '^' || r == '_' || r == '`' || r == '|' || r == '~'
}

// Global validator instance
var DefaultValidator = NewInputValidator()
