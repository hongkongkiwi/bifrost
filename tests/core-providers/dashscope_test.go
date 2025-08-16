package coreproviders_test

import (
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/tests/core-providers/config"
	"github.com/maximhq/bifrost/tests/core-providers/scenarios"
)

func TestDashscopeQwenProvider(t *testing.T) {
	// Skip if no Dashscope key is configured
	account := config.GetTestAccount()
	keys := account.GetKeysForProvider(schemas.Dashscope)
	if len(keys) == 0 {
		t.Skip("No Dashscope keys configured, skipping tests")
	}

	testConfig := scenarios.TestConfig{
		TestName:       "Dashscope/Qwen",
		Provider:       schemas.Dashscope,
		Model:          "qwen-turbo",
		Account:        account,
		StreamRequest:  false,
		RunLoadTest:    false,
		RunSystemTests: true,
	}

	scenarios.RunSimpleChat(t, testConfig)
	scenarios.RunMultiTurnConversation(t, testConfig)
}

func TestDashscopeQwenProviderWithImages(t *testing.T) {
	// Skip if no Dashscope key is configured
	account := config.GetTestAccount()
	keys := account.GetKeysForProvider(schemas.Dashscope)
	if len(keys) == 0 {
		t.Skip("No Dashscope keys configured, skipping tests")
	}

	testConfig := scenarios.TestConfig{
		TestName:       "Dashscope/Qwen with Images",
		Provider:       schemas.Dashscope,
		Model:          "qwen-vl-plus", // Vision model
		Account:        account,
		StreamRequest:  false,
		RunLoadTest:    false,
		RunSystemTests: false,
	}

	// Test with image URLs if the model supports it
	scenarios.RunImageURL(t, testConfig)
}