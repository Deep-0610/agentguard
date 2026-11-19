package scanner

import (
	"strings"
	"testing"

	"github.com/Deep-0610/agentguard/internal/model"
)

func TestAdversarialInputsAreRedactedAndDetected(t *testing.T) {
	secret := "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	cases := []struct {
		name         string
		server       model.Server
		wantLocation string
	}{
		{"split token flag", model.Server{Name: "demo", Config: "mcp.json", Args: []string{"--token", secret}}, "args[1]"},
		{"inline token flag", model.Server{Name: "demo", Config: "mcp.json", Args: []string{"--token=" + secret}}, "args[0]"},
		{"URL username", model.Server{Name: "demo", Config: "mcp.json", URL: "https://" + secret + "@example.test/mcp"}, "url.userinfo"},
		{"URL fragment", model.Server{Name: "demo", Config: "mcp.json", URL: "https://example.test/mcp#access_token=" + secret}, "url.fragment"},
		{"tool declaration", model.Server{Name: "demo", Config: "mcp.json", Tools: []map[string]any{{"description": secret}}}, "tools[0]"},
		{"JSON credential property", model.Server{Name: "demo", Config: "mcp.json", Tools: []map[string]any{{"api_key": "ordinary-but-sensitive-value"}}}, "tools[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := Analyze([]model.Server{tc.server})
			found := false
			for _, f := range findings {
				if f.Location == tc.wantLocation {
					found = true
					if strings.Contains(f.Evidence, secret) || f.Evidence != "[REDACTED]" {
						t.Fatalf("sensitive value not fully redacted: %q", f.Evidence)
					}
				}
			}
			if !found {
				t.Fatalf("expected finding at %s; got %#v", tc.wantLocation, findings)
			}
		})
	}
}

func TestFindingResourceDoesNotEchoSecretServerName(t *testing.T) {
	secret := "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	findings := Analyze([]model.Server{{Name: secret, Config: "/tmp/" + secret + "/mcp.json", Env: map[string]string{"TOKEN": "value"}}})
	for _, f := range findings {
		if strings.Contains(f.Resource, secret) {
			t.Fatalf("secret leaked through resource: %q", f.Resource)
		}
	}
}

func TestRedactDoesNotRetainPrefixOrSuffix(t *testing.T) {
	value := "prefix-ghp_abcdefghijklmnopqrstuvwxyz1234567890-suffix"
	if got := redact(value); got != "[REDACTED]" {
		t.Fatalf("expected complete redaction, got %q", got)
	}
}

func TestSafeLabelStripsTerminalAndBidiControls(t *testing.T) {
	input := "\x1b[31mwarning\x1b[0m\n\u202ehidden"
	got := SafeLabel(input)
	if strings.ContainsAny(got, "\x1b\n\r") {
		t.Fatalf("terminal control character survived sanitization: %q", got)
	}
	if strings.ContainsRune(got, '\u202e') {
		t.Fatalf("bidirectional override survived sanitization: %q", got)
	}
	if got != "warninghidden" {
		t.Fatalf("unexpected sanitized label: %q", got)
	}
}

func TestSafeLabelBoundsUntrustedText(t *testing.T) {
	got := SafeLabel(strings.Repeat("a", 600))
	if len([]rune(got)) > 513 {
		t.Fatalf("label was not bounded: got %d runes", len([]rune(got)))
	}
}

func FuzzRedactNeverRetainsNonEmptyInput(f *testing.F) {
	f.Add("ghp_abcdefghijklmnopqrstuvwxyz1234567890")
	f.Add("password=hunter2")
	f.Add("密碼秘密令牌")
	f.Add("[REDACTED]")
	f.Fuzz(func(t *testing.T, value string) {
		got := redact(value)
		if value != "" && got != "[REDACTED]" {
			t.Fatalf("redaction retained input")
		}
	})
}

func FuzzAnalyzeSensitiveEnvironmentValues(f *testing.F) {
	f.Add("ghp_abcdefghijklmnopqrstuvwxyz1234567890")
	f.Add("ordinary-value")
	f.Add("password=verysecretvalue")
	f.Fuzz(func(t *testing.T, value string) {
		findings := Analyze([]model.Server{{Name: "fuzz", Config: "mcp.json", Env: map[string]string{"TOKEN": value}}})
		for _, finding := range findings {
			if value != "" && value != "[REDACTED]" && finding.Evidence == value {
				t.Fatalf("finding evidence retained sensitive input")
			}
		}
	})
}

func TestRepeatedURLCredentialsHaveUniqueFindingIDs(t *testing.T) {
	secretA := "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	secretB := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	findings := Analyze([]model.Server{{Name: "demo", Config: "mcp.json", URL: "https://example.test/mcp?token=" + secretA + "&token=" + secretB}})
	seen := map[string]bool{}
	count := 0
	for _, finding := range findings {
		if strings.HasPrefix(finding.Location, "url.query.token[") {
			count++
			if seen[finding.ID] {
				t.Fatalf("duplicate finding ID %q", finding.ID)
			}
			seen[finding.ID] = true
		}
	}
	if count != 2 {
		t.Fatalf("expected two distinct URL credential findings, got %d", count)
	}
}
