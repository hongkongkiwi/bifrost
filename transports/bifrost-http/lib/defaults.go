// Package lib provides default configuration values for the Bifrost HTTP transport.
package lib

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// Default configuration values
const (
	DefaultPort               = 8080
	DefaultHost               = "0.0.0.0"
	DefaultTimeout            = 30 * time.Second
	DefaultMaxRequestSize     = 10 * 1024 * 1024 // 10MB
	DefaultRateLimit          = 100              // requests per second
	DefaultInitialPoolSize    = 10
	DefaultDropExcessRequests = false
	DefaultEnableLogging      = true
	DefaultEnableGovernance   = false
	DefaultAllowDirectKeys    = true
	DefaultEnableCaching      = false
	DefaultCacheTTLSeconds    = 300 // 5 minutes
	DefaultCacheDB            = 0
)

// GetDefaultClientConfig returns the default client configuration
func GetDefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		DropExcessRequests:      getEnvBool("BIFROST_DROP_EXCESS_REQUESTS", DefaultDropExcessRequests),
		InitialPoolSize:         getEnvInt("BIFROST_INITIAL_POOL_SIZE", DefaultInitialPoolSize),
		PrometheusLabels:        []string{},
		EnableLogging:           getEnvBool("BIFROST_ENABLE_LOGGING", DefaultEnableLogging),
		EnableGovernance:        getEnvBool("BIFROST_ENABLE_GOVERNANCE", DefaultEnableGovernance),
		EnforceGovernanceHeader: getEnvBool("BIFROST_ENFORCE_GOVERNANCE_HEADER", false),
		AllowDirectKeys:         getEnvBool("BIFROST_ALLOW_DIRECT_KEYS", DefaultAllowDirectKeys),
		EnableCaching:           getEnvBool("BIFROST_ENABLE_CACHING", DefaultEnableCaching),
		AllowedOrigins:          getEnvStringSlice("BIFROST_ALLOWED_ORIGINS", []string{}),
	}
}

// GetDefaultCacheConfig returns the default cache configuration
func GetDefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Addr:            getEnvString("BIFROST_CACHE_ADDR", "localhost:6379"),
		Username:        getEnvString("BIFROST_CACHE_USERNAME", ""),
		Password:        getEnvString("BIFROST_CACHE_PASSWORD", ""),
		DB:              getEnvInt("BIFROST_CACHE_DB", DefaultCacheDB),
		TTLSeconds:      getEnvInt("BIFROST_CACHE_TTL_SECONDS", DefaultCacheTTLSeconds),
		Prefix:          getEnvString("BIFROST_CACHE_PREFIX", "bifrost:"),
		CacheByModel:    getEnvBool("BIFROST_CACHE_BY_MODEL", true),
		CacheByProvider: getEnvBool("BIFROST_CACHE_BY_PROVIDER", true),
	}
}

// GetDefaultNetworkConfig returns the default network configuration for providers
func GetDefaultNetworkConfig() *schemas.NetworkConfig {
	return &schemas.NetworkConfig{
		BaseURL:                        getEnvString("BIFROST_PROVIDER_BASE_URL", ""),
		ExtraHeaders:                   make(map[string]string),
		DefaultRequestTimeoutInSeconds: getEnvInt("BIFROST_REQUEST_TIMEOUT", 30),
		MaxRetries:                     getEnvInt("BIFROST_MAX_RETRIES", 3),
		RetryBackoffInitial:            time.Duration(getEnvInt("BIFROST_RETRY_BACKOFF_MS", 500)) * time.Millisecond,
		RetryBackoffMax:                time.Duration(getEnvInt("BIFROST_RETRY_BACKOFF_MAX_MS", 5000)) * time.Millisecond,
	}
}

// GetDefaultConcurrencyConfig returns the default concurrency configuration
func GetDefaultConcurrencyConfig() *schemas.ConcurrencyAndBufferSize {
	return &schemas.ConcurrencyAndBufferSize{
		Concurrency: getEnvInt("BIFROST_CONCURRENCY", 10),
		BufferSize:  getEnvInt("BIFROST_BUFFER_SIZE", 100),
	}
}

// GetDefaultBifrostHTTPConfig returns a complete default configuration
func GetDefaultBifrostHTTPConfig() *BifrostHTTPConfig {
	return &BifrostHTTPConfig{
		ClientConfig:   GetDefaultClientConfig(),
		ProviderConfig: make(ConfigMap),
		MCPConfig:      GetDefaultMCPConfig(),
	}
}

// GetDefaultMCPConfig returns the default MCP configuration with environment variable support
func GetDefaultMCPConfig() *schemas.MCPConfig {
	if !getEnvBool("BIFROST_MCP_ENABLED", false) {
		return nil
	}

	return &schemas.MCPConfig{
		Servers: []schemas.MCPServerConfig{},
		Options: schemas.MCPOptions{
			MaxConnections:  getEnvInt("BIFROST_MCP_MAX_CONNECTIONS", 10),
			ConnectionTTL:   time.Duration(getEnvInt("BIFROST_MCP_CONNECTION_TTL_SECONDS", 300)) * time.Second,
			RequestTimeout:  time.Duration(getEnvInt("BIFROST_MCP_REQUEST_TIMEOUT_SECONDS", 30)) * time.Second,
			RetryAttempts:   getEnvInt("BIFROST_MCP_RETRY_ATTEMPTS", 3),
			RetryDelay:      time.Duration(getEnvInt("BIFROST_MCP_RETRY_DELAY_MS", 1000)) * time.Millisecond,
			EnableCaching:   getEnvBool("BIFROST_MCP_ENABLE_CACHING", true),
			CacheTTL:        time.Duration(getEnvInt("BIFROST_MCP_CACHE_TTL_SECONDS", 60)) * time.Second,
			EnabledFeatures: getEnvStringSlice("BIFROST_MCP_ENABLED_FEATURES", []string{"tools", "prompts", "resources"}),
		},
	}
}

// MergeWithDefaults merges a partial configuration with defaults
func MergeWithDefaults(config *BifrostHTTPConfig) *BifrostHTTPConfig {
	if config == nil {
		return GetDefaultBifrostHTTPConfig()
	}

	// Merge client config
	if config.ClientConfig == nil {
		config.ClientConfig = GetDefaultClientConfig()
	} else {
		defaultClient := GetDefaultClientConfig()
		// Only set defaults for zero values
		if config.ClientConfig.InitialPoolSize == 0 {
			config.ClientConfig.InitialPoolSize = defaultClient.InitialPoolSize
		}
		if len(config.ClientConfig.AllowedOrigins) == 0 {
			config.ClientConfig.AllowedOrigins = defaultClient.AllowedOrigins
		}
	}

	// Merge provider configs
	if config.ProviderConfig == nil {
		config.ProviderConfig = make(ConfigMap)
	}

	// Apply default network config to providers without one
	for provider, providerConfig := range config.ProviderConfig {
		if providerConfig.NetworkConfig == nil {
			providerConfig.NetworkConfig = GetDefaultNetworkConfig()
		}
		if providerConfig.ConcurrencyAndBufferSize == nil {
			providerConfig.ConcurrencyAndBufferSize = GetDefaultConcurrencyConfig()
		}
		config.ProviderConfig[provider] = providerConfig
	}

	// Merge MCP config
	if config.MCPConfig == nil {
		config.MCPConfig = GetDefaultMCPConfig()
	}

	return config
}

// Helper functions to read environment variables

func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvStringSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Simple comma-separated parsing
		return splitAndTrim(value, ",")
	}
	return defaultValue
}

func splitAndTrim(s, sep string) []string {
	parts := []string{}
	for _, part := range strings.Split(s, sep) {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}