package report

import (
	"strings"
	"testing"

	"github.com/Deep-0610/agentguard/internal/model"
	"github.com/Deep-0610/agentguard/internal/scanner"
)

func TestRenderFormatsDoNotExposeConfigurationSecrets(t *testing.T) {
	secret := "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	server := model.Server{
		Name: secret,
		Config: "/tmp/" + secret + "/mcp.json",
		Command: "node",
		Args: []string{"--token", "password=supersecretvalue"},
		URL: "https://example.test/mcp?api_key=privatecredentialvalue",
		Env: map[string]string{"GITHUB_TOKEN": secret},
		Tools: []map[string]any{{"example": secret}},
		Metadata: map[string]interface{}{"credential": secret},
	}
	findings := scanner.Analyze([]model.Server{server})
	for _, format := range []string{"json", "html", "sarif", "table"} {
		output, err := Render(format, []model.Server{server}, findings)
		if err != nil {
			t.Fatalf("%s render failed: %v", format, err)
		}
		for _, forbidden := range []string{secret, "supersecretvalue", "privatecredentialvalue"} {
			if strings.Contains(string(output), forbidden) {
				t.Fatalf("%s report leaked sensitive value %q", format, forbidden)
			}
		}
	}
}
