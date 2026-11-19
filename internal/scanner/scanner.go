package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Deep-0610/agentguard/internal/model"
)

var secretPatterns = []struct {
	name     string
	re       *regexp.Regexp
	severity string
}{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "critical"},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{30,}`), "critical"},
	{"Slack token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{20,}`), "high"},
	{"Private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), "critical"},
	{"Generic credential assignment", regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|token|client[_-]?secret|password)\s*[:=]\s*["']?[^\s"'{}]{8,}`), "high"},
}

var sensitiveEnvName = regexp.MustCompile(`(?i)(?:secret|token|password|api[_-]?key|private[_-]?key|credential|auth)`)
var shellNames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true,
	"fish": true, "ksh": true, "csh": true, "tcsh": true,
	"cmd": true, "cmd.exe": true, "powershell": true, "pwsh": true,
}

func Analyze(servers []model.Server) []model.Finding {
	var findings []model.Finding
	for _, server := range servers {
		findings = append(findings, inspectServer(server)...)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Score == findings[j].Score {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Score > findings[j].Score
	})
	return findings
}

func inspectServer(s model.Server) []model.Finding {
	var out []model.Finding
	resource := safeResource(s)

	for key, value := range s.Env {
		if value == "" {
			continue
		}
		location := "env." + key
		if finding, ok := inspectSecret(s, resource, location, key, value); ok {
			out = append(out, finding)
		}
	}

	if s.Command != "" {
		if finding, ok := inspectSecret(s, resource, "command", "command", s.Command); ok {
			out = append(out, finding)
		}
		if shell, ok := shellExecutable(s.Command); ok {
			out = append(out, model.Finding{
				ID: id("execution", s.Config, s.Name, shell), Severity: "medium", Category: "execution-risk",
				Title: "Shell-based MCP launch", Description: "The server is configured to start through a shell. Review command construction and argument boundaries.",
				Resource: resource, Location: "command", Evidence: "shell executable: " + shell,
				Remediation: "Prefer a fixed executable with explicit arguments; avoid shell interpolation.",
				Score: 45, Tags: []string{"process", "execution"},
			})
		}
	}

	for i, arg := range s.Args {
		location := fmt.Sprintf("args[%d]", i)
		if strings.HasPrefix(arg, "-") {
			flag, inline, hasInline := strings.Cut(strings.TrimLeft(arg, "-"), "=")
			if sensitiveEnvName.MatchString(flag) {
				if hasInline && inline != "" {
					out = append(out, secretFinding(s, resource, location, flag, "Credential in command-line flag", "high", inline))
				} else if i+1 < len(s.Args) && !strings.HasPrefix(s.Args[i+1], "-") {
					out = append(out, secretFinding(s, resource, fmt.Sprintf("args[%d]", i+1), flag, "Credential in command-line flag", "high", s.Args[i+1]))
				}
			}
		}
		if finding, ok := inspectSecret(s, resource, location, location, arg); ok {
			out = append(out, finding)
		}
	}

	if s.URL != "" {
		parsed, err := url.Parse(s.URL)
		if err == nil {
			if strings.EqualFold(parsed.Scheme, "http") {
				out = append(out, model.Finding{
					ID: id("transport", s.Config, s.Name, "http"), Severity: "high", Category: "transport-security",
					Title: "Unencrypted remote MCP endpoint", Description: "The configured remote endpoint uses HTTP rather than HTTPS.",
					Resource: resource, Location: "url", Evidence: "scheme: http",
					Remediation: "Use HTTPS with certificate validation for remote MCP traffic.",
					Score: 75, Tags: []string{"network", "tls"},
				})
			}
			if parsed.User != nil {
				username := parsed.User.Username()
				password, hasPassword := parsed.User.Password()
				if username != "" || (hasPassword && password != "") {
					out = append(out, secretFinding(s, resource, "url.userinfo", "url.userinfo", "Credential embedded in remote URL", "critical", username+":"+password))
				}
			}
			for key, values := range parsed.Query() {
				if sensitiveEnvName.MatchString(key) {
					for _, value := range values {
						if value != "" {
							out = append(out, secretFinding(s, resource, "url.query."+key, "url.query."+key, "Credential in URL query", "high", value))
						}
					}
				}
			}
			if parsed.Fragment != "" {
				if finding, ok := inspectSecret(s, resource, "url.fragment", "url.fragment", parsed.Fragment); ok {
					out = append(out, finding)
				}
			}
		}
	}

	if len(s.Tools) > 0 {
		for i, tool := range s.Tools {
			data, err := jsonMarshal(tool)
			if err == nil {
				location := fmt.Sprintf("tools[%d]", i)
				if finding, ok := inspectSecret(s, resource, location, location, string(data)); ok {
					out = append(out, finding)
				}
			}
		}
		hash := schemaHash(s.Tools)
		out = append(out, model.Finding{
			ID: id("fingerprint", s.Config, s.Name, hash), Severity: "info", Category: "schema-fingerprint",
			Title: "Tool schema fingerprint", Description: "A deterministic SHA-256 fingerprint was calculated for tool declarations in this configuration.",
			Resource: resource, Location: "tools", Evidence: hash,
			Remediation: "Store this fingerprint in a trusted baseline and alert when it changes unexpectedly.",
			Score: 0, Tags: []string{"integrity", "drift"},
		})
	}
	return out
}

func inspectSecret(s model.Server, resource, location, key, value string) (model.Finding, bool) {
	if value == "" {
		return model.Finding{}, false
	}
	for _, pattern := range secretPatterns {
		if pattern.re.MatchString(value) {
			return secretFinding(s, resource, location, key, pattern.name, pattern.severity, value), true
		}
	}
	if sensitiveEnvName.MatchString(key) {
		return secretFinding(s, resource, location, key, "Potential secret in sensitive field", "high", value), true
	}
	return model.Finding{}, false
}

func secretFinding(s model.Server, resource, location, key, title, severity, value string) model.Finding {
	return model.Finding{
		ID: id("secret", s.Config, s.Name, location, key), Severity: severity, Category: "secret-exposure",
		Title: title, Description: "A value matched a credential heuristic or appeared in a field whose name indicates sensitive data. This is a heuristic finding; AgentGuard does not validate credentials.",
		Resource: resource, Location: SafeLabel(location), Evidence: redact(value),
		Remediation: "Move credentials to an OS-backed secret store or managed secret provider. If this value was exposed, rotate it using the provider's approved process.",
		Score: severityScore(severity), Tags: []string{"secret", "credential"},
	}
}

func shellExecutable(command string) (string, bool) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "", false
	}
	executable := strings.Trim(fields[0], "\"' ")
	name := strings.ToLower(filepath.Base(executable))
	return name, shellNames[name]
}

func schemaHash(tools []map[string]any) string {
	data, _ := jsonMarshal(tools)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func id(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8])
}

func redact(value string) string {
	if value == "" {
		return ""
	}
	return "[REDACTED]"
}

var secretAssignment = regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|token|client[_-]?secret|password)\s*[:=]\s*[^\s,;]+`)

func SafeLabel(value string) string {
	if value == "" {
		return ""
	}
	for _, pattern := range secretPatterns {
		if pattern.re.MatchString(value) {
			return "[REDACTED]"
		}
	}
	if secretAssignment.MatchString(value) {
		return "[REDACTED]"
	}
	return value
}

func safeResource(s model.Server) string {
	name := SafeLabel(s.Name)
	config := SafeLabel(filepath.Base(s.Config))
	return name + " (" + config + ")"
}

func severityScore(severity string) int {
	switch severity {
	case "critical":
		return 100
	case "high":
		return 75
	case "medium":
		return 45
	default:
		return 20
	}
}
