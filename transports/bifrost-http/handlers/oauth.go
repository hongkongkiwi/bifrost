package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fasthttp/router"
	bifrost "github.com/maximhq/bifrost/core"
	schemas "github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// OAuthHandler provides a minimal Anthropic OAuth login flow (Authorization Code + PKCE).
// It exchanges a code for an access token and stores it as an Anthropic provider key.
// NOTE: This initial version stores only the access token (no automatic refresh).
// Configure via env or config management in your deployment:
//   - ANTHROPIC_OAUTH_CLIENT_ID
//   - ANTHROPIC_OAUTH_AUTH_URL (e.g., https://accounts.anthropic.com/authorize)
//   - ANTHROPIC_OAUTH_TOKEN_URL (e.g., https://accounts.anthropic.com/oauth/token)
//   - ANTHROPIC_OAUTH_REDIRECT_URL (defaults to http://localhost:8080/oauth/anthropic/callback)
//   - ANTHROPIC_OAUTH_SCOPES (space-separated)

type OAuthHandler struct {
	store  *lib.ConfigStore
	client *bifrost.Bifrost
	logger schemas.Logger

	mu              sync.Mutex
	stateToVerifier map[string]string
	stateExpiry     map[string]time.Time
    stateToMode     map[string]string
}

func NewOAuthHandler(store *lib.ConfigStore, client *bifrost.Bifrost, logger schemas.Logger) *OAuthHandler {
	return &OAuthHandler{
		store:          store,
		client:         client,
		logger:         logger,
		stateToVerifier: make(map[string]string),
        stateExpiry:     make(map[string]time.Time),
        stateToMode:     make(map[string]string),
	}
}

func (h *OAuthHandler) RegisterRoutes(r *router.Router) {
	r.GET("/oauth/anthropic/start", h.StartAnthropicOAuth)
	r.GET("/oauth/anthropic/callback", h.CallbackAnthropicOAuth)
    // Qwen (Alibaba/DashScope) flow – similar to Anthropic console mode but env-driven endpoints
    r.GET("/oauth/qwen/start", h.StartQwenOAuth)
    r.GET("/oauth/qwen/callback", h.CallbackQwenOAuth)
    // Simple GUI portal and key save endpoint
    r.GET("/oauth", h.OAuthPortal)
    r.POST("/oauth/qwen/save-key", h.SaveQwenAPIKey)
    // GitHub Copilot device flow
    r.GET("/oauth/copilot/start", h.StartCopilotDevice)
    r.GET("/oauth/copilot/poll", h.PollCopilotDevice)
}

func (h *OAuthHandler) StartAnthropicOAuth(ctx *fasthttp.RequestCtx) {
    // Mode can be "max" (Claude Pro/Max) or "console" (API key creation). Default to "max".
    mode := strings.TrimSpace(string(ctx.QueryArgs().Peek("mode")))
    if mode == "" {
        mode = "max"
    }

    clientID := strings.TrimSpace(string(ctx.QueryArgs().Peek("client_id")))
	if clientID == "" {
		clientID = strings.TrimSpace(os.Getenv("ANTHROPIC_OAUTH_CLIENT_ID"))
	}
    // Set sensible defaults based on opencode implementation
    authURL := strings.TrimSpace(os.Getenv("ANTHROPIC_OAUTH_AUTH_URL"))
    if authURL == "" {
        if mode == "console" {
            authURL = "https://console.anthropic.com/oauth/authorize"
        } else {
            authURL = "https://claude.ai/oauth/authorize"
        }
    }
    tokenURL := strings.TrimSpace(os.Getenv("ANTHROPIC_OAUTH_TOKEN_URL"))
    if tokenURL == "" {
        tokenURL = "https://console.anthropic.com/v1/oauth/token"
    }
	if clientID == "" || authURL == "" || tokenURL == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Missing OAuth configuration. Set ANTHROPIC_OAUTH_CLIENT_ID, ANTHROPIC_OAUTH_AUTH_URL, ANTHROPIC_OAUTH_TOKEN_URL.", h.logger)
		return
	}

	redirectURI := strings.TrimSpace(os.Getenv("ANTHROPIC_OAUTH_REDIRECT_URL"))
	if redirectURI == "" {
		// default to local server callback
		redirectURI = fmt.Sprintf("http://%s/oauth/anthropic/callback", ctx.LocalAddr())
	}
    scopes := strings.TrimSpace(os.Getenv("ANTHROPIC_OAUTH_SCOPES"))
    if qScopes := strings.TrimSpace(string(ctx.QueryArgs().Peek("scopes"))); qScopes != "" {
        scopes = qScopes
    }
	if scopes == "" {
        // Defaults used by opencode: org:create_api_key user:profile user:inference
        scopes = "org:create_api_key user:profile user:inference"
	}

	state := randomURLSafe(24)
	verifier := randomURLSafe(32)
	challenge := pkceS256(verifier)

	h.mu.Lock()
	h.stateToVerifier[state] = verifier
	h.stateExpiry[state] = time.Now().Add(10 * time.Minute)
    h.stateToMode[state] = mode
	h.mu.Unlock()

	u, err := url.Parse(authURL)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid ANTHROPIC_OAUTH_AUTH_URL", h.logger)
		return
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scopes)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

    // Return a small HTML page that redirects the user
	html := fmt.Sprintf("<html><body><script>location.href='%s'</script>Redirecting to login...</body></html>", htmlEscape(u.String()))
	ctx.SetContentType("text/html; charset=utf-8")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString(html)
}

func (h *OAuthHandler) CallbackAnthropicOAuth(ctx *fasthttp.RequestCtx) {
	code := string(ctx.QueryArgs().Peek("code"))
	state := string(ctx.QueryArgs().Peek("state"))
	if code == "" || state == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Missing code or state", h.logger)
		return
	}

	h.mu.Lock()
    verifier, ok := h.stateToVerifier[state]
	exp, expOK := h.stateExpiry[state]
    mode := h.stateToMode[state]
	if ok {
		delete(h.stateToVerifier, state)
	}
	if expOK {
		delete(h.stateExpiry, state)
	}
    if mode != "" {
        delete(h.stateToMode, state)
    }
	h.mu.Unlock()

	if !ok || time.Now().After(exp) {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid or expired state", h.logger)
		return
	}

	clientID := strings.TrimSpace(os.Getenv("ANTHROPIC_OAUTH_CLIENT_ID"))
	tokenURL := strings.TrimSpace(os.Getenv("ANTHROPIC_OAUTH_TOKEN_URL"))
	redirectURI := strings.TrimSpace(os.Getenv("ANTHROPIC_OAUTH_REDIRECT_URL"))
	if redirectURI == "" {
		redirectURI = fmt.Sprintf("http://%s/oauth/anthropic/callback", ctx.LocalAddr())
	}
	if clientID == "" || tokenURL == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Missing OAuth configuration.", h.logger)
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to create token request", h.logger)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("Token endpoint error: %v", err), h.logger)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("Token endpoint returned status %d", resp.StatusCode), h.logger)
		return
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		SendError(ctx, fasthttp.StatusBadGateway, "Failed to parse token response", h.logger)
		return
	}
	if tokenResp.AccessToken == "" {
		SendError(ctx, fasthttp.StatusBadGateway, "Empty access_token in response", h.logger)
		return
	}

    // If mode is "console", try to exchange the access token for an API key via Anthropic CLI endpoint
    storedValue := tokenResp.AccessToken
    if mode == "console" {
        req, _ := http.NewRequest("POST", "https://api.anthropic.com/api/oauth/claude_cli/create_api_key", strings.NewReader(""))
        req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("Accept", "application/json, text/plain, */*")
        httpClient := &http.Client{Timeout: 15 * time.Second}
        resp2, err2 := httpClient.Do(req)
        if err2 == nil && resp2 != nil && resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
            defer resp2.Body.Close()
            var out struct{ RawKey string `json:"raw_key"` }
            if err := json.NewDecoder(resp2.Body).Decode(&out); err == nil && out.RawKey != "" {
                storedValue = out.RawKey
            }
        }
    }

    // Store/merge into Anthropic provider keys
    provider := schemas.Anthropic
    cfg, err := h.store.GetProviderConfigRaw(provider)
    if err != nil {
        // create provider with this key/token
        newCfg := lib.ProviderConfig{
            Keys: []schemas.Key{{
                ID:     randomURLSafe(12),
                Value:  storedValue,
                Models: []string{},
                Weight: 1.0,
            }},
        }
        if err := h.store.AddProvider(provider, newCfg); err != nil {
            SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to add provider: %v", err), h.logger)
            return
        }
    } else {
        // append as a new key
        keys := append(cfg.Keys, schemas.Key{
            ID:     randomURLSafe(12),
            Value:  storedValue,
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
        if err := h.store.UpdateProviderConfig(provider, newCfg); err != nil {
            SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update provider: %v", err), h.logger)
            return
        }
    }

	if err := h.store.SaveConfig(); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to persist configuration: %v", err), h.logger)
		return
	}

	// Success page
	success := "<html><body><h3>Anthropic login successful</h3><p>Token stored. You can close this window.</p></body></html>"
	ctx.SetContentType("text/html; charset=utf-8")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString(success)
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "'", "&#39;", "\"", "&quot;")
	return r.Replace(s)
}

// StartQwenOAuth begins the Qwen (Alibaba/DashScope) OAuth flow. Requires env endpoints.
// Required env vars:
//   - QWEN_OAUTH_CLIENT_ID
//   - QWEN_OAUTH_AUTH_URL
//   - QWEN_OAUTH_TOKEN_URL
// Optional:
//   - QWEN_OAUTH_REDIRECT_URL (defaults to http://<host>/oauth/qwen/callback)
//   - QWEN_OAUTH_SCOPES
func (h *OAuthHandler) StartQwenOAuth(ctx *fasthttp.RequestCtx) {
    clientID := strings.TrimSpace(string(ctx.QueryArgs().Peek("client_id")))
    if clientID == "" {
        clientID = strings.TrimSpace(os.Getenv("QWEN_OAUTH_CLIENT_ID"))
    }
    authURL := strings.TrimSpace(os.Getenv("QWEN_OAUTH_AUTH_URL"))
    tokenURL := strings.TrimSpace(os.Getenv("QWEN_OAUTH_TOKEN_URL"))
    if clientID == "" || authURL == "" || tokenURL == "" {
        SendError(ctx, fasthttp.StatusBadRequest, "Missing Qwen OAuth configuration. Set QWEN_OAUTH_CLIENT_ID, QWEN_OAUTH_AUTH_URL, QWEN_OAUTH_TOKEN_URL.", h.logger)
        return
    }

    redirectURI := strings.TrimSpace(os.Getenv("QWEN_OAUTH_REDIRECT_URL"))
    if redirectURI == "" {
        redirectURI = fmt.Sprintf("http://%s/oauth/qwen/callback", ctx.LocalAddr())
    }
    scopes := strings.TrimSpace(os.Getenv("QWEN_OAUTH_SCOPES"))
    if qScopes := strings.TrimSpace(string(ctx.QueryArgs().Peek("scopes"))); qScopes != "" {
        scopes = qScopes
    }
    if scopes == "" {
        scopes = "openid profile" // sensible default; override via env if needed
    }

    state := randomURLSafe(24)
    verifier := randomURLSafe(32)
    challenge := pkceS256(verifier)

    h.mu.Lock()
    h.stateToVerifier[state] = verifier
    h.stateExpiry[state] = time.Now().Add(10 * time.Minute)
    // mark as qwen in mode map to disambiguate (optional)
    h.stateToMode[state] = "qwen"
    h.mu.Unlock()

    u, err := url.Parse(authURL)
    if err != nil {
        SendError(ctx, fasthttp.StatusBadRequest, "Invalid QWEN_OAUTH_AUTH_URL", h.logger)
        return
    }
    q := u.Query()
    q.Set("response_type", "code")
    q.Set("client_id", clientID)
    q.Set("redirect_uri", redirectURI)
    q.Set("scope", scopes)
    q.Set("state", state)
    q.Set("code_challenge", challenge)
    q.Set("code_challenge_method", "S256")
    u.RawQuery = q.Encode()

    html := fmt.Sprintf("<html><body><script>location.href='%s'</script>Redirecting to login...</body></html>", htmlEscape(u.String()))
    ctx.SetContentType("text/html; charset=utf-8")
    ctx.SetStatusCode(fasthttp.StatusOK)
    ctx.SetBodyString(html)
}

// CallbackQwenOAuth exchanges code → token and then creates a DashScope API key (if configured), storing it.
// Requires:
//   - QWEN_OAUTH_CLIENT_ID, QWEN_OAUTH_TOKEN_URL
// Optional:
//   - QWEN_OAUTH_REDIRECT_URL
//   - QWEN_OAUTH_CREATE_KEY_URL (if set, will call it with Bearer token and expect JSON { raw_key | api_key | key })
func (h *OAuthHandler) CallbackQwenOAuth(ctx *fasthttp.RequestCtx) {
    code := string(ctx.QueryArgs().Peek("code"))
    state := string(ctx.QueryArgs().Peek("state"))
    if code == "" || state == "" {
        SendError(ctx, fasthttp.StatusBadRequest, "Missing code or state", h.logger)
        return
    }

    h.mu.Lock()
    verifier, ok := h.stateToVerifier[state]
    exp, expOK := h.stateExpiry[state]
    if ok {
        delete(h.stateToVerifier, state)
    }
    if expOK {
        delete(h.stateExpiry, state)
    }
    delete(h.stateToMode, state)
    h.mu.Unlock()

    if !ok || time.Now().After(exp) {
        SendError(ctx, fasthttp.StatusBadRequest, "Invalid or expired state", h.logger)
        return
    }

    clientID := strings.TrimSpace(os.Getenv("QWEN_OAUTH_CLIENT_ID"))
    tokenURL := strings.TrimSpace(os.Getenv("QWEN_OAUTH_TOKEN_URL"))
    redirectURI := strings.TrimSpace(os.Getenv("QWEN_OAUTH_REDIRECT_URL"))
    if redirectURI == "" {
        redirectURI = fmt.Sprintf("http://%s/oauth/qwen/callback", ctx.LocalAddr())
    }
    if clientID == "" || tokenURL == "" {
        SendError(ctx, fasthttp.StatusBadRequest, "Missing Qwen OAuth configuration.", h.logger)
        return
    }

    form := url.Values{}
    form.Set("grant_type", "authorization_code")
    form.Set("code", code)
    form.Set("client_id", clientID)
    form.Set("redirect_uri", redirectURI)
    form.Set("code_verifier", verifier)

    req, err := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
    if err != nil {
        SendError(ctx, fasthttp.StatusInternalServerError, "Failed to create token request", h.logger)
        return
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    httpClient := &http.Client{Timeout: 15 * time.Second}
    resp, err := httpClient.Do(req)
    if err != nil {
        SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("Token endpoint error: %v", err), h.logger)
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("Token endpoint returned status %d", resp.StatusCode), h.logger)
        return
    }

    var tokenResp struct {
        AccessToken  string `json:"access_token"`
        TokenType    string `json:"token_type"`
        RefreshToken string `json:"refresh_token"`
        ExpiresIn    int    `json:"expires_in"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        SendError(ctx, fasthttp.StatusBadGateway, "Failed to parse token response", h.logger)
        return
    }
    if tokenResp.AccessToken == "" {
        SendError(ctx, fasthttp.StatusBadGateway, "Empty access_token in response", h.logger)
        return
    }

    // Optionally create a DashScope API key via configured endpoint
    storedValue := ""
    createKeyURL := strings.TrimSpace(os.Getenv("QWEN_OAUTH_CREATE_KEY_URL"))
    if createKeyURL != "" {
        req2, _ := http.NewRequest("POST", createKeyURL, strings.NewReader(""))
        req2.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
        req2.Header.Set("Content-Type", "application/json")
        req2.Header.Set("Accept", "application/json, text/plain, */*")
        resp2, err2 := httpClient.Do(req2)
        if err2 == nil && resp2 != nil && resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
            defer resp2.Body.Close()
            var out map[string]interface{}
            if err := json.NewDecoder(resp2.Body).Decode(&out); err == nil {
                // Try common key field names
                if v, ok := out["raw_key"].(string); ok && v != "" {
                    storedValue = v
                } else if v, ok := out["api_key"].(string); ok && v != "" {
                    storedValue = v
                } else if v, ok := out["key"].(string); ok && v != "" {
                    storedValue = v
                }
            }
        }
    }
    if storedValue == "" {
        // fallback to using the access token directly
        storedValue = tokenResp.AccessToken
    }

    // Store under OpenAI provider. If provider doesn't exist, create with DashScope base URL.
    provider := schemas.OpenAI
    cfg, err := h.store.GetProviderConfigRaw(provider)
    if err != nil {
        dashScopeBase := "https://dashscope.aliyuncs.com/compatible-mode/v1"
        newCfg := lib.ProviderConfig{
            Keys: []schemas.Key{{
                ID:     randomURLSafe(12),
                Value:  storedValue,
                Models: []string{},
                Weight: 1.0,
            }},
            NetworkConfig: &schemas.NetworkConfig{BaseURL: dashScopeBase},
        }
        if err := h.store.AddProvider(provider, newCfg); err != nil {
            SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to add provider: %v", err), h.logger)
            return
        }
    } else {
        keys := append(cfg.Keys, schemas.Key{
            ID:     randomURLSafe(12),
            Value:  storedValue,
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
        if newCfg.NetworkConfig == nil || newCfg.NetworkConfig.BaseURL == "" {
            if newCfg.NetworkConfig == nil {
                nc := schemas.DefaultNetworkConfig
                newCfg.NetworkConfig = &nc
            }
            newCfg.NetworkConfig.BaseURL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
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

    success := "<html><body><h3>Qwen login successful</h3><p>Credential stored. You can close this window.</p></body></html>"
    ctx.SetContentType("text/html; charset=utf-8")
    ctx.SetStatusCode(fasthttp.StatusOK)
    ctx.SetBodyString(success)
}

// OAuthPortal serves a minimal HTML GUI to initiate Anthropic login and paste Qwen DashScope API key.
func (h *OAuthHandler) OAuthPortal(ctx *fasthttp.RequestCtx) {
    host := string(ctx.Host())
    if host == "" {
        host = "localhost:8080"
    }
    base := "http://" + host
    html := fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"/><title>OAuth & API Keys</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu;max-width:720px;margin:40px auto;padding:0 16px;color:#222}
section{border:1px solid #ddd;border-radius:8px;padding:16px;margin-bottom:20px}
label{display:block;margin:8px 0 4px}input,select{padding:8px;width:100%%;box-sizing:border-box}
button{margin-top:12px;padding:10px 14px;border:0;background:#111;color:#fff;border-radius:6px;cursor:pointer}
.row{display:flex;gap:8px}.row>div{flex:1}</style></head>
<body>
  <h2>Connect Providers</h2>
  <section>
    <h3>Anthropic (Claude)</h3>
    <p>Sign in with your Anthropic account. No environment variables needed.</p>
    <div class="row">
      <div>
        <label>Client ID</label>
        <input id="anth-client" placeholder="YOUR_CLIENT_ID"/>
      </div>
      <div>
        <label>Mode</label>
        <select id="anth-mode">
          <option value="max">Claude Pro/Max</option>
          <option value="console">Console (Create API Key)</option>
        </select>
      </div>
    </div>
    <button onclick="startAnth()">Sign in</button>
  </section>

  <section>
    <h3>Qwen (DashScope)</h3>
    <p>Use DashScope's OpenAI-compatible API key. Paste once; Bifrost will store it for routing to Qwen.</p>
    <form method="POST" action="/oauth/qwen/save-key">
      <label>DashScope API Key</label>
      <input name="api_key" placeholder="ds-..." required />
      <button type="submit">Save API Key</button>
    </form>
  </section>

  <section>
    <h3>GitHub Copilot</h3>
    <p>Sign in with GitHub (device flow). We’ll fetch the Copilot token and store it for routing.</p>
    <div id="copilot">
      <button onclick="startCopilot()">Start GitHub Device Login</button>
      <div id="copilot-info" style="margin-top:10px"></div>
    </div>
  </section>

<script>
function startAnth(){
  const id = document.getElementById('anth-client').value.trim();
  const mode = document.getElementById('anth-mode').value;
  if(!id){ alert('Enter client id'); return; }
  const u = new URL('%s/oauth/anthropic/start', window.location.origin);
  u.searchParams.set('client_id', id);
  u.searchParams.set('mode', mode);
  window.location = u.toString();
}

async function startCopilot(){
  const info = document.getElementById('copilot-info');
  info.textContent = 'Starting device flow...';
  try {
    const res = await fetch('%s/oauth/copilot/start');
    if(!res.ok){ info.textContent = 'Failed to start.'; return; }
    const data = await res.json();
    info.innerHTML = 'Visit: <b>'+data.verification_uri+'</b><br/>Enter code: <b>'+data.user_code+'</b>';
    // Poll until complete
    const poll = async ()=>{
      const r = await fetch('%s/oauth/copilot/poll?device_code='+encodeURIComponent(data.device_code)+'&interval='+encodeURIComponent(data.interval));
      if(r.status===202){ setTimeout(poll, (data.interval||5)*1000); return; }
      if(!r.ok){ info.textContent = 'Failed to authorize.'; return; }
      info.textContent = 'Login successful. Copilot is ready.';
    };
    setTimeout(poll, (data.interval||5)*1000);
  } catch(e){ info.textContent = 'Error: '+e; }
}
</script>
// inject host for startCopilot URLs
`, base, base, base)

    ctx.SetContentType("text/html; charset=utf-8")
    ctx.SetStatusCode(fasthttp.StatusOK)
    ctx.SetBodyString(html)
}

// SaveQwenAPIKey persists a DashScope API key under OpenAI provider with DashScope base URL
func (h *OAuthHandler) SaveQwenAPIKey(ctx *fasthttp.RequestCtx) {
    apiKey := strings.TrimSpace(string(ctx.PostArgs().Peek("api_key")))
    if apiKey == "" {
        SendError(ctx, fasthttp.StatusBadRequest, "Missing api_key", h.logger)
        return
    }

    provider := schemas.OpenAI
    cfg, err := h.store.GetProviderConfigRaw(provider)
    if err != nil {
        dashScopeBase := "https://dashscope.aliyuncs.com/compatible-mode/v1"
        newCfg := lib.ProviderConfig{
            Keys: []schemas.Key{{
                ID:     randomURLSafe(12),
                Value:  apiKey,
                Models: []string{},
                Weight: 1.0,
            }},
            NetworkConfig: &schemas.NetworkConfig{BaseURL: dashScopeBase},
        }
        if err := h.store.AddProvider(provider, newCfg); err != nil {
            SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to add provider: %v", err), h.logger)
            return
        }
    } else {
        keys := append(cfg.Keys, schemas.Key{
            ID:     randomURLSafe(12),
            Value:  apiKey,
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
        if newCfg.NetworkConfig == nil || newCfg.NetworkConfig.BaseURL == "" {
            if newCfg.NetworkConfig == nil {
                nc := schemas.DefaultNetworkConfig
                newCfg.NetworkConfig = &nc
            }
            newCfg.NetworkConfig.BaseURL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
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

    success := "<html><body><h3>DashScope API key saved</h3><p>OpenAI-compatible calls will route to Qwen via DashScope.</p><p><a href=\"/oauth\">Back</a></p></body></html>"
    ctx.SetContentType("text/html; charset=utf-8")
    ctx.SetStatusCode(fasthttp.StatusOK)
    ctx.SetBodyString(success)
}

// StartCopilotDevice starts GitHub device code flow and returns JSON with codes
func (h *OAuthHandler) StartCopilotDevice(ctx *fasthttp.RequestCtx) {
    // Constants from opencode flow
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
    // Return JSON for the GUI to render
    ctx.SetContentType("application/json")
    ctx.SetStatusCode(fasthttp.StatusOK)
    b, _ := json.Marshal(out)
    ctx.SetBody(b)
}

// PollCopilotDevice polls GitHub for OAuth access token, then fetches Copilot token and stores it
func (h *OAuthHandler) PollCopilotDevice(ctx *fasthttp.RequestCtx) {
    deviceCode := string(ctx.QueryArgs().Peek("device_code"))
    intervalStr := string(ctx.QueryArgs().Peek("interval"))
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

    // Store under OpenAI provider with Copilot endpoint if provided
    provider := schemas.OpenAI
    cfg, err := h.store.GetProviderConfigRaw(provider)
    apiBase := strings.TrimSpace(cop.Endpoints.API)
    if apiBase == "" {
        apiBase = "https://copilot-proxy.githubusercontent.com/v1"
    }
    if err != nil {
        newCfg := lib.ProviderConfig{
            Keys: []schemas.Key{{
                ID:     randomURLSafe(12),
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
        keys := append(cfg.Keys, schemas.Key{
            ID:     randomURLSafe(12),
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
