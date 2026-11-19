package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Deep-0610/agentguard/internal/model"
)

var secretPatterns = []struct {
	name string
	re *regexp.Regexp
	severity string
}{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "critical"},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{30,}`), "critical"},
	{"Slack token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{20,}`), "high"},
	{"Private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), "critical"},
	{"Generic credential assignment", regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*["']?[^\s"'{}]{8,}`), "high"},
}
var sensitiveEnvName = regexp.MustCompile(`(?i)(?:secret|token|password|api[_-]?key|private[_-]?key)`)

func Analyze(servers []model.Server) []model.Finding {
	var findings []model.Finding
	for _, server := range servers {
		findings = append(findings, inspectServer(server)...)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Score == findings[j].Score { return findings[i].ID < findings[j].ID }
		return findings[i].Score > findings[j].Score
	})
	return findings
}

func inspectServer(s model.Server) []model.Finding {
	var out []model.Finding
	resource := s.Name + " (" + s.Config + ")"
	for key, value := range s.Env {
		if value == "" { continue }
		matched := false
		for _, pattern := range secretPatterns {
			if pattern.re.MatchString(value) {
				out = append(out, secretFinding(s, resource, key, pattern.name, pattern.severity, value))
				matched = true
				break
			}
		}
		if !matched && sensitiveEnvName.MatchString(key) {
			out = append(out, secretFinding(s, resource, key, "Potential secret in sensitive environment variable", "high", value))
		}
	}
	if s.Command != "" && isShell(s.Command) {
		out = append(out, model.Finding{
			ID: id("execution", s.Name, s.Command), Severity: "medium", Category: "execution-risk",
			Title: "Shell-based MCP launch", Description: "The server is configured to start through a shell. Review command construction and argument boundaries.",
			Resource: resource, Location: "command", Evidence: s.Command, Remediation: "Prefer a fixed executable with explicit arguments; avoid shell interpolation.",
			Score: 45, Tags: []string{"process", "execution"},
		})
	}
	if s.URL != "" && strings.HasPrefix(strings.ToLower(s.URL), "http://") {
		out = append(out, model.Finding{
			ID: id("transport", s.Name, s.URL), Severity: "high", Category: "transport-security",
			Title: "Unencrypted remote MCP endpoint", Description: "The configured remote endpoint uses HTTP rather than HTTPS.",
			Resource: resource, Location: "url", Evidence: s.URL, Remediation: "Use HTTPS with certificate validation for remote MCP traffic.",
			Score: 75, Tags: []string{"network", "tls"},
		})
	}
	if len(s.Tools) > 0 {
		hash := schemaHash(s.Tools)
		out = append(out, model.Finding{
			ID: id("fingerprint", s.Name, hash), Severity: "info", Category: "schema-fingerprint",
			Title: "Tool schema fingerprint", Description: "A deterministic SHA-256 fingerprint was calculated for tool declarations in this configuration.",
			Resource: resource, Location: "tools", Evidence: hash, Remediation: "Store this fingerprint in a trusted baseline and alert when it changes unexpectedly.",
			Score: 0, Tags: []string{"integrity", "drift"},
		})
	}
	return out
}

func secretFinding(s model.Server, resource, key, title, severity, value string) model.Finding {
	return model.Finding{
		ID: id("secret", s.Name, key), Severity: severity, Category: "secret-exposure",
		Title: title + " in MCP environment", Description: "A value matching a credential heuristic or stored under a sensitive environment variable name.",
		Resource: resource, Location: "env." + key, Evidence: redact(value),
		Remediation: "Move credentials to an OS-backed secret store or managed secret provider; rotate exposed credentials.",
		Score: severityScore(severity), Tags: []string{"secret", "credential"},
	}
}

func schemaHash(tools []map[string]any) string {
	data, _ := jsonMarshal(tools)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func id(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:8])
}

func redact(value string) string {
	if len(value) <= 8 { return "[REDACTED]" }
	return fmt.Sprintf("%s…%s [REDACTED]", value[:3], value[len(value)-3:])
}

func severityScore(severity string) int {
	switch severity { case "critical": return 100; case "high": return 75; case "medium": return 45; default: return 20 }
}

func isShell(command string) bool {
	base := strings.ToLower(command)
	return strings.Contains(base, "sh") || strings.Contains(base, "cmd.exe") || strings.Contains(base, "powershell")
}
