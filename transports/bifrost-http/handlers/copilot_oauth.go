package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fasthttp/router"
	bifrost "github.com/maximhq/bifrost/core"
	schemas "github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// CopilotOAuthHandler provides GitHub Copilot device flow authentication
// It handles the device code flow to get GitHub OAuth tokens and exchanges them for Copilot API tokens
type CopilotOAuthHandler struct {
	store  *lib.ConfigStore
	client *bifrost.Bifrost
	logger schemas.Logger
}

func NewCopilotOAuthHandler(store *lib.ConfigStore, client *bifrost.Bifrost, logger schemas.Logger) *CopilotOAuthHandler {
	return &CopilotOAuthHandler{
		store:  store,
		client: client,
		logger: logger,
	}
}

func (h *CopilotOAuthHandler) RegisterRoutes(r *router.Router) {
	// GitHub Copilot device flow
	r.GET("/oauth/copilot/start", h.StartCopilotDevice)
	r.GET("/oauth/copilot/poll", h.PollCopilotDevice)
}

// StartCopilotDevice starts GitHub device code flow and returns JSON with codes
func (h *CopilotOAuthHandler) StartCopilotDevice(ctx *fasthttp.RequestCtx) {
	// Constants from GitHub Copilot integration
	const clientID = "Iv1.b507a08c87ecfe98"
	deviceCodeURL := "https://github.com/login/device/code"

	body := map[string]string{
		"client_id": clientID,
		"scope":     "read:user",
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", deviceCodeURL, strings.NewReader(string(jsonBody)))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GitHubCopilotChat/0.26.7")

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadGateway, "Failed to start device flow", h.logger)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("Device code error: %s", resp.Status), h.logger)
		return
	}
	var out struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		SendError(ctx, fasthttp.StatusBadGateway, "Invalid device response", h.logger)
		return
	}
	// Return JSON for the client to render
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	b, _ := json.Marshal(out)
	ctx.SetBody(b)
}

// PollCopilotDevice polls GitHub for OAuth access token, then fetches Copilot token and stores it
func (h *CopilotOAuthHandler) PollCopilotDevice(ctx *fasthttp.RequestCtx) {
	deviceCode := string(ctx.QueryArgs().Peek("device_code"))
	if deviceCode == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Missing device_code", h.logger)
		return
	}
	const clientID = "Iv1.b507a08c87ecfe98"
	accessTokenURL := "https://github.com/login/oauth/access_token"
	copilotAPIKeyURL := "https://api.github.com/copilot_internal/v2/token"

	body := map[string]string{
		"client_id":   clientID,
		"device_code": deviceCode,
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
	}
	jsonBody, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", accessTokenURL, strings.NewReader(string(jsonBody)))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GitHubCopilotChat/0.26.7")

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		SendError(ctx, fasthttp.StatusAccepted, "pending", h.logger) // keep polling
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 428 || resp.StatusCode == 202 { // pending
		ctx.SetStatusCode(fasthttp.StatusAccepted)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("Access token error: %s", resp.Status), h.logger)
		return
	}
	var tokenOut struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenOut); err != nil {
		ctx.SetStatusCode(fasthttp.StatusAccepted)
		return
	}
	if tokenOut.AccessToken == "" {
		ctx.SetStatusCode(fasthttp.StatusAccepted)
		return
	}

	// Exchange for Copilot API token
	req2, _ := http.NewRequest("GET", copilotAPIKeyURL, nil)
	req2.Header.Set("Accept", "application/json")
	req2.Header.Set("Authorization", "Bearer "+tokenOut.AccessToken)
	req2.Header.Set("User-Agent", "GitHubCopilotChat/0.26.7")
	req2.Header.Set("Editor-Version", "vscode/1.99.3")
	req2.Header.Set("Editor-Plugin-Version", "copilot-chat/0.26.7")
	resp2, err := httpClient.Do(req2)
	if err != nil || resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
		SendError(ctx, fasthttp.StatusBadGateway, "Failed to fetch Copilot token", h.logger)
		return
	}
	defer resp2.Body.Close()
	var cop struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
		Endpoints struct{ API string `json:"api"` } `json:"endpoints"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&cop); err != nil || cop.Token == "" {
		SendError(ctx, fasthttp.StatusBadGateway, "Invalid Copilot token response", h.logger)
		return
	}

	// Store under OpenAI provider with Copilot endpoint
	provider := schemas.OpenAI
	cfg, err := h.store.GetProviderConfigRaw(provider)
	apiBase := strings.TrimSpace(cop.Endpoints.API)
	if apiBase == "" {
		apiBase = "https://copilot-proxy.githubusercontent.com/v1"
	}
	
	keyID := randomURLSafe(12)
	if err != nil {
		// Create new provider config with Copilot endpoint
		newCfg := lib.ProviderConfig{
			Keys: []schemas.Key{{
				ID:     keyID,
				Value:  cop.Token,
				Models: []string{},
				Weight: 1.0,
			}},
			NetworkConfig: &schemas.NetworkConfig{BaseURL: apiBase},
		}
		if err := h.store.AddProvider(provider, newCfg); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to add provider: %v", err), h.logger)
			return
		}
	} else {
		// Append to existing provider
		keys := append(cfg.Keys, schemas.Key{
			ID:     keyID,
			Value:  cop.Token,
			Models: []string{},
			Weight: 1.0,
		})
		newCfg := lib.ProviderConfig{
			Keys:                     keys,
			NetworkConfig:            cfg.NetworkConfig,
			ConcurrencyAndBufferSize: cfg.ConcurrencyAndBufferSize,
			ProxyConfig:              cfg.ProxyConfig,
			SendBackRawResponse:      cfg.SendBackRawResponse,
		}
		// Set Copilot endpoint if not already configured
		if newCfg.NetworkConfig == nil || newCfg.NetworkConfig.BaseURL == "" {
			if newCfg.NetworkConfig == nil {
				nc := schemas.DefaultNetworkConfig
				newCfg.NetworkConfig = &nc
			}
			newCfg.NetworkConfig.BaseURL = apiBase
		}
		if err := h.store.UpdateProviderConfig(provider, newCfg); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update provider: %v", err), h.logger)
			return
		}
	}

	if err := h.store.SaveConfig(); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to persist configuration: %v", err), h.logger)
		return
	}

	// Success
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}