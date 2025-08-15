package interfaces

import "time"

// TODO third party providers

type NetworkConfig struct {
	DefaultRequestTimeoutInSeconds int           `json:"default_request_timeout_in_seconds"`
	MaxRetries                     int           `json:"max_retries"`
	RetryBackoffInitial            time.Duration `json:"retry_backoff_initial"`
	RetryBackoffMax                time.Duration `json:"retry_backoff_max"`
}

type MetaConfig struct {
	SecretAccessKey   *string           `json:"secret_access_key,omitempty"`
	Region            *string           `json:"region,omitempty"`
	SessionToken      *string           `json:"session_token,omitempty"`
	ARN               *string           `json:"arn,omitempty"`
	InferenceProfiles map[string]string `json:"inference_profiles,omitempty"`
}

type ConcurrencyAndBufferSize struct {
	Concurrency int `json:"concurrency"`
	BufferSize  int `json:"buffer_size"`
}

// Validate ensures concurrency and buffer size are within acceptable ranges
func (c *ConcurrencyAndBufferSize) Validate() error {
	if c.Concurrency <= 0 {
		c.Concurrency = 1 // Default to 1 if invalid
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 100 // Default to 100 if invalid
	}
	return nil
}

// ProxyType defines the type of proxy to use
type ProxyType string

const (
	NoProxy     ProxyType = "none"
	HttpProxy   ProxyType = "http"
	Socks5Proxy ProxyType = "socks5"
	EnvProxy    ProxyType = "environment"
)

// ProxyConfig holds proxy configuration
type ProxyConfig struct {
	Type     ProxyType `json:"type"`     // Type of proxy (none, http, socks5, environment)
	URL      string    `json:"url"`      // Proxy URL (for http and socks5)
	Username string    `json:"username"` // Optional username for proxy authentication
	Password string    `json:"password"` // Optional password for proxy authentication
}

type ProviderConfig struct {
	NetworkConfig            NetworkConfig            `json:"network_config"`
	MetaConfig               *MetaConfig              `json:"meta_config,omitempty"`
	ConcurrencyAndBufferSize ConcurrencyAndBufferSize `json:"concurrency_and_buffer_size"`
	Logger                   Logger                   `json:"logger"`
	ProxyConfig              *ProxyConfig             `json:"proxy_config,omitempty"`
}

// Provider defines the interface for AI model providers
type Provider interface {
	GetProviderKey() SupportedModelProvider
	TextCompletion(model, key, text string, params *ModelParameters) (*BifrostResponse, *BifrostError)
	ChatCompletion(model, key string, messages []Message, params *ModelParameters) (*BifrostResponse, *BifrostError)
}
