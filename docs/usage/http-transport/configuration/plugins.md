# 🔌 Plugin Configuration

Guide to configuring custom plugins in Bifrost HTTP transport for middleware functionality.

> **💡 Status:** Plugin configuration via JSON is under development. Currently, plugins are loaded via command-line flags.

---

## 📋 Plugin Overview

Bifrost plugins provide middleware functionality:

- **Request/response processing** and modification
- **Authentication and authorization** controls
- **Rate limiting** and traffic shaping
- **Monitoring and metrics** collection
- **Custom business logic** injection

### **Current Plugin Loading (Command-line)**

**NPM:**

```bash
npx -y @maximhq/bifrost -plugins "maxim,custom-plugin"
```

**Docker:**

```bash
docker run -p 8080:8080 \
  -v $(pwd)/config.json:/app/config/config.json \
  -e OPENAI_API_KEY \
  -e APP_PLUGINS=maxim,custom-plugin \
  maximhq/bifrost
```

---

## 🔧 Available Plugins

### **Maxim Logger Plugin**

Official logging and analytics plugin:

```bash
# Environment variables required
export MAXIM_API_KEY="your-maxim-api-key"
export MAXIM_LOG_REPO_ID="your-repo-id"

# Start with Maxim plugin
npx -y @maximhq/bifrost -plugins "maxim"
```

**Features:**

- Request/response logging to Maxim platform
- Performance analytics and insights
- Error tracking and debugging
- Usage pattern analysis

### **Prometheus Metrics Plugin**

Built-in metrics collection (always loaded):

```bash
# Access metrics
curl http://localhost:8080/metrics
```

**Metrics provided:**

- Request count and latency
- Provider performance
- Error rates and types
- Resource utilization

---

## 🛠️ Custom Plugin Development

### **Plugin Interface**

Plugins implement the `schemas.Plugin` interface:

```go
type Plugin interface {
    Name() string
    ProcessRequest(ctx BifrostContext, req *BifrostRequest) (*BifrostRequest, *BifrostError)
    ProcessResponse(ctx BifrostContext, req *BifrostRequest, resp *BifrostResponse) (*BifrostResponse, *BifrostError)
}
```

### **Example Plugin Structure**

```go
package myplugin

import (
    "github.com/maximhq/bifrost/core/schemas"
)

type MyPlugin struct {
    config MyPluginConfig
}

func NewMyPlugin(config MyPluginConfig) *MyPlugin {
    return &MyPlugin{config: config}
}

func (p *MyPlugin) Name() string {
    return "my-plugin"
}

func (p *MyPlugin) ProcessRequest(
    ctx schemas.BifrostContext,
    req *schemas.BifrostRequest,
) (*schemas.BifrostRequest, *schemas.BifrostError) {
    // Process incoming request
    // Add headers, validate, modify, etc.
    return req, nil
}

func (p *MyPlugin) ProcessResponse(
    ctx schemas.BifrostContext,
    req *schemas.BifrostRequest,
    resp *schemas.BifrostResponse,
) (*schemas.BifrostResponse, *schemas.BifrostError) {
    // Process outgoing response
    // Log, transform, add metadata, etc.
    return resp, nil
}
```

---

## 📋 Plugin Use Cases

### **Authentication Plugin**

```go
func (p *AuthPlugin) ProcessRequest(
    ctx schemas.BifrostContext,
    req *schemas.BifrostRequest,
) (*schemas.BifrostRequest, *schemas.BifrostError) {
    // Extract API key from headers
    apiKey := ctx.GetHeader("X-API-Key")

    // Validate against database/service
    if !p.validateAPIKey(apiKey) {
        return nil, &schemas.BifrostError{
            Message: "Invalid API key",
            StatusCode: &[]int{401}[0],
        }
    }

    return req, nil
}
```

### **Rate Limiting Plugin**

```go
func (p *RateLimitPlugin) ProcessRequest(
    ctx schemas.BifrostContext,
    req *schemas.BifrostRequest,
) (*schemas.BifrostRequest, *schemas.BifrostError) {
    clientIP := ctx.GetClientIP()

    if !p.limiter.Allow(clientIP) {
        return nil, &schemas.BifrostError{
            Message: "Rate limit exceeded",
            StatusCode: &[]int{429}[0],
        }
    }

    return req, nil
}
```

### **Request Transformation Plugin**

```go
func (p *TransformPlugin) ProcessRequest(
    ctx schemas.BifrostContext,
    req *schemas.BifrostRequest,
) (*schemas.BifrostRequest, *schemas.BifrostError) {
    // Add organization context to messages
    if req.Input.ChatCompletionInput != nil {
        messages := *req.Input.ChatCompletionInput

        // Add system message with org context
        orgContext := schemas.BifrostMessage{
            Role: "system",
            Content: schemas.MessageContent{
                Text: p.getOrganizationContext(ctx),
            },
        }

        messages = append([]schemas.BifrostMessage{orgContext}, messages...)
        req.Input.ChatCompletionInput = &messages
    }

    return req, nil
}
```

---

## 🔮 Future JSON Configuration

**Planned configuration format** (under development):

```json
{
  "providers": {
    "openai": {
      "keys": [
        {
          "value": "env.OPENAI_API_KEY",
          "models": ["gpt-4o-mini"],
          "weight": 1.0
        }
      ]
    }
  },
  "plugins": [
    {
      "name": "maxim",
      "source": "../../plugins/maxim",
      "type": "local",
      "config": {
        "api_key": "env.MAXIM_API_KEY",
        "log_repo_id": "env.MAXIM_LOG_REPO_ID"
      }
    },
    {
      "name": "mocker",
      "source": "../../plugins/mocker",
      "type": "local",
      "config": {
        "enabled": true,
        "default_behavior": "passthrough",
        "rules": [
          {
            "name": "test-mock",
            "enabled": true,
            "priority": 1,
            "probability": 1,
            "conditions": {
              "providers": ["openai"]
            },
            "responses": [
              {
                "type": "success",
                "weight": 1.0,
                "content": {
                  "message": "This is a mock response for testing"
                }
              }
            ]
          }
        ]
      }
    }
  ]
}
```

---

## 🧪 Testing Custom Plugins

### **Unit Testing**

```go
func TestMyPlugin(t *testing.T) {
    plugin := NewMyPlugin(MyPluginConfig{})

    ctx := &schemas.BifrostContext{}
    req := &schemas.BifrostRequest{
        Provider: "openai",
        Model: "gpt-4o-mini",
    }

    processedReq, err := plugin.ProcessRequest(ctx, req)

    assert.Nil(t, err)
    assert.NotNil(t, processedReq)
    // Add your assertions
}
```

### **Integration Testing**

```bash
# Build plugin
go build -buildmode=plugin -o myplugin.so ./plugins/myplugin

# Test with HTTP transport
npx -y @maximhq/bifrost -plugins "myplugin"

# Send test request
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Test-Header: test-value" \
  -d '{
    "provider": "openai",
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "test"}]
  }'
```

---

## 🔧 Plugin Execution Order

Plugins execute in loading order:

```bash
# This order: auth -> rate-limit -> maxim -> request
npx -y @maximhq/bifrost -plugins "auth,rate-limit,maxim"
```

**Request flow:**

1. `auth.ProcessRequest()`
2. `rate-limit.ProcessRequest()`
3. `maxim.ProcessRequest()`
4. **Provider request**
5. `maxim.ProcessResponse()`
6. `rate-limit.ProcessResponse()`
7. `auth.ProcessResponse()`

---

## 📚 Related Documentation

- **[🌐 HTTP Transport Overview](../README.md)** - Main HTTP transport guide
- **[🔧 Provider Configuration](./providers.md)** - Configure AI providers
- **[🛠️ MCP Configuration](./mcp.md)** - External tool integration
- **[🔌 Go Package Plugins](../../go-package/plugins.md)** - Plugin development guide

> **🏛️ Architecture:** For plugin system design and performance details, see [Architecture Documentation](../../../architecture/README.md).

> **🛠️ Development:** Full plugin development guide and examples available in [Go Package Plugins](../../go-package/plugins.md).
