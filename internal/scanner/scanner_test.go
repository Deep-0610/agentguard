package scanner

import (
	"strings"
	"testing"

	"github.com/Deep-0610/agentguard/internal/model"
)

func TestAnalyzeDetectsCredentialWithoutLeakingIt(t *testing.T) {
	secret := "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	findings := Analyze([]model.Server{{Name: "demo", Config: "mcp.json", Env: map[string]string{"GITHUB_TOKEN": secret}}})
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("unexpected severity: %s", findings[0].Severity)
	}
	if strings.Contains(findings[0].Evidence, secret) {
		t.Fatal("secret leaked into evidence")
	}
	if strings.Contains(findings[0].ID, secret) {
		t.Fatal("secret leaked into finding ID")
	}
}

func TestAnalyzeFlagsHTTPWithoutEchoingURL(t *testing.T) {
	findings := Analyze([]model.Server{{Name: "remote", Config: "mcp.json", URL: "http://example.test/mcp?token=should-not-appear"}})
	if len(findings) != 2 {
		t.Fatalf("expected transport and URL credential findings, got %#v", findings)
	}
	for _, finding := range findings {
		if strings.Contains(finding.Evidence, "should-not-appear") {
			t.Fatal("URL credential leaked into evidence")
		}
	}
}

func TestAnalyzeFindsSecretsInArgsAndCommand(t *testing.T) {
	secret := "password=supersecretvalue"
	findings := Analyze([]model.Server{{Name: "demo", Config: "mcp.json", Command: "node", Args: []string{"--config", secret}}})
	if len(findings) != 1 {
		t.Fatalf("expected one argument finding, got %#v", findings)
	}
	if strings.Contains(findings[0].Evidence, secret) {
		t.Fatal("argument secret leaked into evidence")
	}
}

func TestShellDetectionUsesExecutableName(t *testing.T) {
	if _, ok := shellExecutable("node ./shell-runner.js"); ok {
		t.Fatal("non-shell executable was incorrectly flagged")
	}
	if shell, ok := shellExecutable("/bin/bash -lc run"); !ok || shell != "bash" {
		t.Fatalf("expected bash detection, got %q %v", shell, ok)
	}
}

func TestRedactHandlesUnicode(t *testing.T) {
	value := "密碼秘密令牌"
	if got := redact(value); !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected redaction, got %q", got)
	}
}

func TestSchemaFingerprintIsStable(t *testing.T) {
	tools := []map[string]any{{"name": "search", "description": "Search"}}
	if schemaHash(tools) != schemaHash(tools) {
		t.Fatal("fingerprint is not stable")
	}
}
