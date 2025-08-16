// Package lib provides routing rules for the Bifrost HTTP transport.
package lib

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sync"

	"github.com/maximhq/bifrost/core/schemas"
)

// RouteRule defines a routing rule for request distribution
type RouteRule struct {
	Name          string                 `json:"name"`           // Rule name for identification
	Pattern       string                 `json:"pattern"`        // URL pattern (regex)
	Method        string                 `json:"method"`         // HTTP method (GET, POST, etc.) or "*" for any
	Provider      schemas.ModelProvider  `json:"provider"`       // Target provider
	ModelOverride string                 `json:"model_override"` // Override model name
	Headers       map[string]string      `json:"headers"`        // Required headers to match
	Priority      int                    `json:"priority"`       // Rule priority (higher = more important)
	Enabled       bool                   `json:"enabled"`        // Whether the rule is active
	Metadata      map[string]interface{} `json:"metadata"`       // Additional metadata
	compiledRegex *regexp.Regexp         // Compiled regex pattern
}

// RouteConfig represents the complete routing configuration
type RouteConfig struct {
	Rules         []RouteRule `json:"rules"`
	DefaultProvider schemas.ModelProvider `json:"default_provider"`
	DefaultModel    string               `json:"default_model"`
}

// Router manages routing rules and request distribution
type Router struct {
	config *RouteConfig
	mu     sync.RWMutex
	logger schemas.Logger
}

// NewRouter creates a new router with the given configuration
func NewRouter(logger schemas.Logger) *Router {
	return &Router{
		config: &RouteConfig{
			Rules: []RouteRule{},
		},
		logger: logger,
	}
}

// LoadRoutingConfig loads routing configuration from a file
func (r *Router) LoadRoutingConfig(configPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read routing config: %w", err)
	}

	var config RouteConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse routing config: %w", err)
	}

	// Compile regex patterns
	for i := range config.Rules {
		if config.Rules[i].Pattern != "" {
			regex, err := regexp.Compile(config.Rules[i].Pattern)
			if err != nil {
				return fmt.Errorf("invalid regex pattern in rule %s: %w", config.Rules[i].Name, err)
			}
			config.Rules[i].compiledRegex = regex
		}
	}

	// Sort rules by priority (higher priority first)
	sortRulesByPriority(config.Rules)

	r.config = &config
	r.logger.Info(fmt.Sprintf("Loaded %d routing rules", len(config.Rules)))
	
	return nil
}

// UpdateRules updates the routing rules dynamically
func (r *Router) UpdateRules(rules []RouteRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Compile regex patterns
	for i := range rules {
		if rules[i].Pattern != "" {
			regex, err := regexp.Compile(rules[i].Pattern)
			if err != nil {
				return fmt.Errorf("invalid regex pattern in rule %s: %w", rules[i].Name, err)
			}
			rules[i].compiledRegex = regex
		}
	}

	sortRulesByPriority(rules)
	r.config.Rules = rules
	
	return nil
}

// RouteRequest determines the provider and model for a request based on routing rules
func (r *Router) RouteRequest(path string, method string, headers map[string]string) (schemas.ModelProvider, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check each rule in priority order
	for _, rule := range r.config.Rules {
		if !rule.Enabled {
			continue
		}

		// Check method
		if rule.Method != "" && rule.Method != "*" && rule.Method != method {
			continue
		}

		// Check pattern
		if rule.compiledRegex != nil && !rule.compiledRegex.MatchString(path) {
			continue
		}

		// Check headers
		if !matchHeaders(rule.Headers, headers) {
			continue
		}

		// Rule matches
		r.logger.Debug(fmt.Sprintf("Request matched routing rule: %s", rule.Name))
		return rule.Provider, rule.ModelOverride
	}

	// No rule matched, use defaults
	return r.config.DefaultProvider, r.config.DefaultModel
}

// GetRules returns the current routing rules
func (r *Router) GetRules() []RouteRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	rules := make([]RouteRule, len(r.config.Rules))
	copy(rules, r.config.Rules)
	return rules
}

// SetDefaultProvider sets the default provider for unmatched requests
func (r *Router) SetDefaultProvider(provider schemas.ModelProvider, model string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	r.config.DefaultProvider = provider
	r.config.DefaultModel = model
}

// matchHeaders checks if the request headers match the required headers
func matchHeaders(required, actual map[string]string) bool {
	for key, value := range required {
		if actualValue, exists := actual[key]; !exists || actualValue != value {
			return false
		}
	}
	return true
}

// sortRulesByPriority sorts rules by priority in descending order
func sortRulesByPriority(rules []RouteRule) {
	// Simple bubble sort for small rule sets
	for i := 0; i < len(rules)-1; i++ {
		for j := 0; j < len(rules)-i-1; j++ {
			if rules[j].Priority < rules[j+1].Priority {
				rules[j], rules[j+1] = rules[j+1], rules[j]
			}
		}
	}
}

// DefaultRoutingRules returns a set of default routing rules
func DefaultRoutingRules() []RouteRule {
	return []RouteRule{
		{
			Name:     "openai-chat",
			Pattern:  "^/v1/chat/completions$",
			Method:   "POST",
			Provider: schemas.OpenAI,
			Priority: 100,
			Enabled:  true,
		},
		{
			Name:     "anthropic-messages",
			Pattern:  "^/v1/messages$",
			Method:   "POST",
			Provider: schemas.Anthropic,
			Priority: 100,
			Enabled:  true,
		},
		{
			Name:     "embeddings",
			Pattern:  "^/v1/embeddings$",
			Method:   "POST",
			Provider: schemas.Cohere,
			Priority: 90,
			Enabled:  true,
		},
		{
			Name:     "audio-transcription",
			Pattern:  "^/v1/audio/transcriptions$",
			Method:   "POST",
			Provider: schemas.OpenAI,
			ModelOverride: "whisper-1",
			Priority: 80,
			Enabled:  true,
		},
		{
			Name:     "audio-speech",
			Pattern:  "^/v1/audio/speech$",
			Method:   "POST",
			Provider: schemas.OpenAI,
			ModelOverride: "tts-1",
			Priority: 80,
			Enabled:  true,
		},
	}
}

// LoadRoutingFromEnv loads routing rules from environment variables
func LoadRoutingFromEnv() *RouteConfig {
	config := &RouteConfig{
		Rules:           DefaultRoutingRules(),
		DefaultProvider: schemas.OpenAI,
		DefaultModel:    "gpt-3.5-turbo",
	}

	// Override default provider from env
	if provider := os.Getenv("BIFROST_DEFAULT_PROVIDER"); provider != "" {
		config.DefaultProvider = schemas.ModelProvider(provider)
	}

	// Override default model from env
	if model := os.Getenv("BIFROST_DEFAULT_MODEL"); model != "" {
		config.DefaultModel = model
	}

	// Load custom rules from env (JSON format)
	if rulesJSON := os.Getenv("BIFROST_ROUTING_RULES"); rulesJSON != "" {
		var customRules []RouteRule
		if err := json.Unmarshal([]byte(rulesJSON), &customRules); err == nil {
			config.Rules = append(config.Rules, customRules...)
		}
	}

	return config
}