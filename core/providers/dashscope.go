// Package providers implements the Dashscope/Qwen provider for Alibaba's language models.
package providers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	schemas "github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

const (
	// DashscopeAPIURL is the base URL for Dashscope API
	DashscopeAPIURL = "https://dashscope.aliyuncs.com/api/v1"
	// DashscopeProvider identifies this provider
	DashscopeProviderType schemas.ModelProvider = "dashscope"
)

// DashscopeProvider implements the Provider interface for Alibaba's Qwen models
type DashscopeProvider struct {
	client *fasthttp.Client
	config *schemas.ProviderConfig
	logger schemas.Logger
}

// DashscopeRequest represents a request to the Dashscope API
type DashscopeRequest struct {
	Model      string                   `json:"model"`
	Input      DashscopeInput          `json:"input"`
	Parameters DashscopeParameters    `json:"parameters,omitempty"`
}

// DashscopeInput represents the input structure for Dashscope
type DashscopeInput struct {
	Messages []DashscopeMessage `json:"messages"`
}

// DashscopeMessage represents a message in the Dashscope format
type DashscopeMessage struct {
	Role    string                 `json:"role"`
	Content interface{}           `json:"content"`
}

// DashscopeParameters represents optional parameters for Dashscope
type DashscopeParameters struct {
	Temperature      *float64 `json:"temperature,omitempty"`
	TopP            *float64 `json:"top_p,omitempty"`
	TopK            *int     `json:"top_k,omitempty"`
	MaxTokens       *int     `json:"max_tokens,omitempty"`
	Stop            []string `json:"stop,omitempty"`
	Stream          bool     `json:"stream,omitempty"`
	IncrementalOutput bool   `json:"incremental_output,omitempty"`
}

// DashscopeResponse represents a response from the Dashscope API
type DashscopeResponse struct {
	Output    DashscopeOutput `json:"output"`
	Usage     DashscopeUsage  `json:"usage"`
	RequestID string          `json:"request_id"`
}

// DashscopeOutput represents the output structure
type DashscopeOutput struct {
	Text         string                 `json:"text,omitempty"`
	FinishReason string                 `json:"finish_reason,omitempty"`
	Choices      []DashscopeChoice     `json:"choices,omitempty"`
}

// DashscopeChoice represents a choice in the response
type DashscopeChoice struct {
	Message      DashscopeMessage `json:"message"`
	FinishReason string          `json:"finish_reason"`
}

// DashscopeUsage represents token usage information
type DashscopeUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// DashscopeErrorResponse represents an error response from Dashscope
type DashscopeErrorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// NewDashscopeProvider creates a new Dashscope provider instance
func NewDashscopeProvider(config *schemas.ProviderConfig, logger schemas.Logger) *DashscopeProvider {
	client := &fasthttp.Client{
		MaxConnsPerHost:     100,
		MaxIdleConnDuration: 90 * time.Second,
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
	}

	// Configure proxy if provided
	if config.NetworkConfig != nil && config.NetworkConfig.ProxyConfig != nil {
		client = configureProxy(client, config.NetworkConfig.ProxyConfig, logger)
	}

	return &DashscopeProvider{
		client: client,
		config: config,
		logger: logger,
	}
}

// GetProviderType returns the provider type
func (p *DashscopeProvider) GetProviderType() schemas.ModelProvider {
	return DashscopeProviderType
}

// ChatCompletion implements the chat completion for Dashscope/Qwen models
func (p *DashscopeProvider) ChatCompletion(
	ctx context.Context,
	model string,
	key schemas.Key,
	messages []schemas.BifrostMessage,
	params *schemas.ModelParameters,
	_ schemas.PostHookRunner,
) (*schemas.BifrostResponse, *schemas.BifrostError) {
	// Validate inputs
	if err := validateProviderInputs(model, key, messages); err != nil {
		return nil, newBifrostOperationError("Input validation failed", err, DashscopeProviderType)
	}

	// Prepare request
	dashscopeMessages, bifrostErr := p.convertMessages(messages)
	if bifrostErr != nil {
		return nil, bifrostErr
	}

	dashscopeReq := DashscopeRequest{
		Model: model,
		Input: DashscopeInput{
			Messages: dashscopeMessages,
		},
		Parameters: p.prepareParameters(params),
	}

	// Create HTTP request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Set up request
	req.SetRequestURI(fmt.Sprintf("%s/services/aigc/text-generation/generation", DashscopeAPIURL))
	req.Header.SetMethod("POST")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", key.Value))
	req.Header.Set("Content-Type", "application/json")

	// Add extra headers if configured
	if p.config.NetworkConfig != nil && p.config.NetworkConfig.ExtraHeaders != nil {
		setExtraHeaders(req, p.config.NetworkConfig.ExtraHeaders, nil)
	}

	// Marshal request body
	body, err := sonic.Marshal(dashscopeReq)
	if err != nil {
		return nil, newBifrostOperationError("Failed to marshal request", err, DashscopeProviderType)
	}
	req.SetBody(body)

	// Make request with context
	if err := makeRequestWithContext(ctx, p.client, req, resp); err != nil {
		return nil, err
	}

	// Handle response
	if resp.StatusCode() != fasthttp.StatusOK {
		var errorResp DashscopeErrorResponse
		if err := sonic.Unmarshal(resp.Body(), &errorResp); err != nil {
			return nil, newBifrostOperationError("Failed to parse error response", err, DashscopeProviderType)
		}
		return nil, newProviderAPIError(errorResp.Message, nil, resp.StatusCode(), DashscopeProviderType, &errorResp.Code, &errorResp.RequestID)
	}

	// Parse successful response
	var dashscopeResp DashscopeResponse
	if err := sonic.Unmarshal(resp.Body(), &dashscopeResp); err != nil {
		return nil, newBifrostOperationError("Failed to parse response", err, DashscopeProviderType)
	}

	// Convert to Bifrost response
	return p.convertResponse(&dashscopeResp, model), nil
}

// StreamChatCompletion implements streaming chat completion for Dashscope/Qwen models
func (p *DashscopeProvider) StreamChatCompletion(
	ctx context.Context,
	model string,
	key schemas.Key,
	messages []schemas.BifrostMessage,
	params *schemas.ModelParameters,
	postHook schemas.PostHookRunner,
) (chan *schemas.BifrostStream, *schemas.BifrostError) {
	// Validate inputs
	if err := validateProviderInputs(model, key, messages); err != nil {
		return nil, newBifrostOperationError("Input validation failed", err, DashscopeProviderType)
	}

	// Create response channel
	responseChan := make(chan *schemas.BifrostStream, 100)

	// For now, return not implemented
	// Full SSE implementation would go here
	close(responseChan)
	return responseChan, newUnsupportedOperationError("Streaming is not yet implemented for Dashscope", "Dashscope")
}

// TextCompletion implements text completion for Dashscope/Qwen models
func (p *DashscopeProvider) TextCompletion(
	ctx context.Context,
	model string,
	key schemas.Key,
	text string,
	params *schemas.ModelParameters,
	_ schemas.PostHookRunner,
) (*schemas.BifrostResponse, *schemas.BifrostError) {
	// Convert text to chat format and use ChatCompletion
	messages := []schemas.BifrostMessage{
		{
			Role: schemas.User,
			Content: schemas.BifrostMessageContent{
				ContentStr: &text,
			},
		},
	}
	return p.ChatCompletion(ctx, model, key, messages, params, nil)
}

// StreamTextCompletion implements streaming text completion
func (p *DashscopeProvider) StreamTextCompletion(
	ctx context.Context,
	model string,
	key schemas.Key,
	text string,
	params *schemas.ModelParameters,
	postHook schemas.PostHookRunner,
) (chan *schemas.BifrostStream, *schemas.BifrostError) {
	return nil, newUnsupportedOperationError("Streaming text completion is not supported", "Dashscope")
}

// SpeechSynthesis is not supported by Dashscope
func (p *DashscopeProvider) SpeechSynthesis(
	ctx context.Context,
	model string,
	key schemas.Key,
	text string,
	params *schemas.ModelParameters,
	_ schemas.PostHookRunner,
) (*schemas.BifrostResponse, *schemas.BifrostError) {
	return nil, newUnsupportedOperationError("Speech synthesis", "Dashscope")
}

// StreamSpeechSynthesis is not supported by Dashscope
func (p *DashscopeProvider) StreamSpeechSynthesis(
	ctx context.Context,
	model string,
	key schemas.Key,
	text string,
	params *schemas.ModelParameters,
	postHook schemas.PostHookRunner,
) (chan *schemas.BifrostStream, *schemas.BifrostError) {
	return nil, newUnsupportedOperationError("Streaming speech synthesis", "Dashscope")
}

// Transcription is not supported by Dashscope
func (p *DashscopeProvider) Transcription(
	ctx context.Context,
	model string,
	key schemas.Key,
	audio []byte,
	params *schemas.ModelParameters,
	_ schemas.PostHookRunner,
) (*schemas.BifrostResponse, *schemas.BifrostError) {
	return nil, newUnsupportedOperationError("Transcription", "Dashscope")
}

// StreamTranscription is not supported by Dashscope
func (p *DashscopeProvider) StreamTranscription(
	ctx context.Context,
	model string,
	key schemas.Key,
	audio []byte,
	params *schemas.ModelParameters,
	postHook schemas.PostHookRunner,
) (chan *schemas.BifrostStream, *schemas.BifrostError) {
	return nil, newUnsupportedOperationError("Streaming transcription", "Dashscope")
}

// convertMessages converts Bifrost messages to Dashscope format
func (p *DashscopeProvider) convertMessages(messages []schemas.BifrostMessage) ([]DashscopeMessage, *schemas.BifrostError) {
	dashscopeMessages := make([]DashscopeMessage, 0, len(messages))

	for _, msg := range messages {
		dashscopeMsg := DashscopeMessage{
			Role: p.convertRole(msg.Role),
		}

		// Handle content
		if msg.Content.ContentStr != nil {
			dashscopeMsg.Content = *msg.Content.ContentStr
		} else if msg.Content.ContentBlocks != nil {
			// Handle multi-modal content
			content := []map[string]interface{}{}
			for _, block := range *msg.Content.ContentBlocks {
				if block.Text != nil {
					content = append(content, map[string]interface{}{
						"type": "text",
						"text": *block.Text,
					})
				}
				if block.ImageURL != nil {
					content = append(content, map[string]interface{}{
						"type": "image",
						"image": block.ImageURL.URL,
					})
				}
			}
			dashscopeMsg.Content = content
		}

		dashscopeMessages = append(dashscopeMessages, dashscopeMsg)
	}

	return dashscopeMessages, nil
}

// convertRole converts Bifrost role to Dashscope role
func (p *DashscopeProvider) convertRole(role schemas.ModelChatMessageRole) string {
	switch role {
	case schemas.System:
		return "system"
	case schemas.User:
		return "user"
	case schemas.Assistant:
		return "assistant"
	default:
		return string(role)
	}
}

// prepareParameters prepares parameters for Dashscope request
func (p *DashscopeProvider) prepareParameters(params *schemas.ModelParameters) DashscopeParameters {
	dashParams := DashscopeParameters{}

	if params != nil {
		dashParams.Temperature = params.Temperature
		dashParams.TopP = params.TopP
		if params.MaxTokens != nil {
			maxTokens := int(*params.MaxTokens)
			dashParams.MaxTokens = &maxTokens
		}
		if params.Stop != nil {
			dashParams.Stop = *params.Stop
		}
	}

	return dashParams
}

// convertResponse converts Dashscope response to Bifrost response
func (p *DashscopeProvider) convertResponse(resp *DashscopeResponse, model string) *schemas.BifrostResponse {
	bifrostResp := &schemas.BifrostResponse{
		ID:       resp.RequestID,
		Object:   "chat.completion",
		Created:  int(time.Now().Unix()),
		Model:    model,
		Provider: DashscopeProviderType,
	}

	// Convert choices
	if len(resp.Output.Choices) > 0 {
		choices := make([]schemas.BifrostChoice, 0, len(resp.Output.Choices))
		for i, choice := range resp.Output.Choices {
			content := ""
			if str, ok := choice.Message.Content.(string); ok {
				content = str
			}
			
			choices = append(choices, schemas.BifrostChoice{
				Index: i,
				Message: schemas.BifrostMessage{
					Role: schemas.ModelChatMessageRole(choice.Message.Role),
					Content: schemas.BifrostMessageContent{
						ContentStr: &content,
					},
				},
				FinishReason: &choice.FinishReason,
			})
		}
		bifrostResp.Choices = choices
	} else if resp.Output.Text != "" {
		// Fallback to text output
		bifrostResp.Choices = []schemas.BifrostChoice{
			{
				Index: 0,
				Message: schemas.BifrostMessage{
					Role: schemas.Assistant,
					Content: schemas.BifrostMessageContent{
						ContentStr: &resp.Output.Text,
					},
				},
				FinishReason: &resp.Output.FinishReason,
			},
		}
	}

	// Set usage
	bifrostResp.Usage = &schemas.ModelUsage{
		PromptTokens:     resp.Usage.InputTokens,
		CompletionTokens: resp.Usage.OutputTokens,
		TotalTokens:      resp.Usage.TotalTokens,
	}

	return bifrostResp
}

// GetConfig returns the provider configuration
func (p *DashscopeProvider) GetConfig() *schemas.ProviderConfig {
	return p.config
}