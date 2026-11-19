package scanner

import (
	"testing"

	"github.com/Deep-0610/agentguard/internal/model"
)

func TestAnalyzeDetectsCredentialWithoutLeakingIt(t *testing.T) {
	secret := "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	findings := Analyze([]model.Server{{Name:"demo", Config:"mcp.json", Env:map[string]string{"GITHUB_TOKEN":secret}}})
	if len(findings) != 1 { t.Fatalf("expected one finding, got %d", len(findings)) }
	if findings[0].Severity != "critical" { t.Fatalf("unexpected severity: %s", findings[0].Severity) }
	if findings[0].Evidence == secret { t.Fatal("secret leaked into evidence") }
}

func TestAnalyzeFlagsHTTP(t *testing.T) {
	findings := Analyze([]model.Server{{Name:"remote", Config:"mcp.json", URL:"http://example.test/mcp"}})
	if len(findings) != 1 || findings[0].Category != "transport-security" { t.Fatalf("unexpected findings: %#v", findings) }
}

func TestSchemaFingerprintIsStable(t *testing.T) {
	tools := []map[string]any{{"name":"search","description":"Search"}}
	if schemaHash(tools) != schemaHash(tools) { t.Fatal("fingerprint is not stable") }
}
