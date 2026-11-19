package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"path/filepath"
	"strings"

	"github.com/Deep-0610/agentguard/internal/model"
	"github.com/Deep-0610/agentguard/internal/scanner"
)

func Render(format string, servers []model.Server, findings []model.Finding) ([]byte, error) {
	safe := safeFindings(findings)
	result := model.Result{Version: "0.1.0", Servers: safeServers(servers), Findings: safe}
	result.Summary.Servers = len(servers)
	result.Summary.Findings = len(findings)
	for _, f := range safe {
		switch f.Severity {
		case "critical": result.Summary.Critical++
		case "high": result.Summary.High++
		case "medium": result.Summary.Medium++
		case "low": result.Summary.Low++
		}
	}
	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(result, "", "  ")
	case "html":
		return renderHTML(result)
	case "sarif":
		return renderSARIF(result)
	case "table":
		return renderTable(result), nil
	default:
		return nil, fmt.Errorf("unsupported format %q (use table, json, html, or sarif)", format)
	}
}

func safeFindings(in []model.Finding) []model.Finding {
	out := make([]model.Finding, len(in))
	for i, finding := range in {
		out[i] = finding
		out[i].Tags = append([]string(nil), finding.Tags...)
		out[i].ID = scanner.SafeLabel(finding.ID)
		out[i].Severity = scanner.SafeLabel(finding.Severity)
		out[i].Category = scanner.SafeLabel(finding.Category)
		out[i].Title = scanner.SafeLabel(finding.Title)
		out[i].Description = scanner.SafeLabel(finding.Description)
		out[i].Resource = scanner.SafeLabel(finding.Resource)
		out[i].Location = scanner.SafeLabel(finding.Location)
		out[i].Remediation = scanner.SafeLabel(finding.Remediation)
		if finding.Category == "secret-exposure" && finding.Evidence != "" {
			out[i].Evidence = "[REDACTED]"
		} else {
			out[i].Evidence = scanner.SafeLabel(finding.Evidence)
		}
		for j, tag := range finding.Tags {
			out[i].Tags[j] = scanner.SafeLabel(tag)
		}
	}
	return out
}

func safeServers(in []model.Server) []model.Server {
	out := make([]model.Server, len(in))
	for i, s := range in {
		out[i] = s
		out[i].Name = scanner.SafeLabel(s.Name)
		out[i].Config = scanner.SafeLabel(filepath.Base(s.Config))
		out[i].Command = ""
		out[i].Args = nil
		out[i].URL = ""
		out[i].Transport = ""
		out[i].Env = nil
		out[i].Tools = nil
		out[i].Metadata = nil
	}
	return out
}

func renderTable(r model.Result) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "AgentGuard %s | servers: %d | findings: %d\n", r.Version, r.Summary.Servers, r.Summary.Findings)
	if len(r.Findings) == 0 { b.WriteString("No findings.\n"); return b.Bytes() }
	fmt.Fprintf(&b, "%-9s %-5s %-28s %s\n", "SEVERITY", "SCORE", "CATEGORY", "TITLE")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "%-9s %-5d %-28s %s\n", strings.ToUpper(f.Severity), f.Score, f.Category, f.Title)
	}
	return b.Bytes()
}

func renderHTML(r model.Result) ([]byte, error) {
	const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AgentGuard report</title><style>body{font:15px system-ui;margin:40px auto;max-width:1100px;padding:0 20px;color:#172033}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:10px;border-bottom:1px solid #ddd}.critical, .high{color:#b42318}.medium{color:#b54708}.muted{color:#667085}</style></head><body><h1>AgentGuard scan report</h1><p class="muted">{{.Summary.Servers}} servers · {{.Summary.Findings}} findings</p><table><thead><tr><th>Severity</th><th>Score</th><th>Category</th><th>Resource</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>{{range .Findings}}<tr><td class="{{.Severity}}">{{.Severity}}</td><td>{{.Score}}</td><td>{{.Category}}</td><td>{{.Resource}}</td><td>{{.Title}}</td><td>{{.Evidence}}</td></tr>{{end}}</tbody></table></body></html>`
	t, err := template.New("report").Parse(page)
	if err != nil { return nil, err }
	var b bytes.Buffer
	err = t.Execute(&b, r)
	return b.Bytes(), err
}

func renderSARIF(r model.Result) ([]byte, error) {
	type message struct {
		Text string `json:"text"`
	}
	type configuration struct {
		Level string `json:"level"`
	}
	type rule struct {
		ID string `json:"id"`
		ShortDescription message `json:"shortDescription"`
		FullDescription message `json:"fullDescription"`
		Help message `json:"help"`
		DefaultConfiguration configuration `json:"defaultConfiguration"`
	}
	type resultItem struct {
		RuleID string `json:"ruleId"`
		Level string `json:"level"`
		Message message `json:"message"`
	}
	type driver struct {
		Name string `json:"name"`
		Rules []rule `json:"rules"`
	}
	type run struct {
		Tool struct {
			Driver driver `json:"driver"`
		} `json:"tool"`
		Results []resultItem `json:"results"`
	}
	doc := struct {
		Version string `json:"version"`
		Schema string `json:"$schema"`
		Runs []run `json:"runs"`
	}{
		Version: "2.1.0",
		Schema: "https://json.schemastore.org/sarif-2.1.0.json",
	}
	var current run
	current.Tool.Driver.Name = "AgentGuard"
	seen := make(map[string]bool)
	for _, f := range r.Findings {
		level := "note"
		if f.Severity == "critical" || f.Severity == "high" {
			level = "error"
		} else if f.Severity == "medium" {
			level = "warning"
		}
		if !seen[f.Category] {
			seen[f.Category] = true
			current.Tool.Driver.Rules = append(current.Tool.Driver.Rules, rule{
				ID: f.Category,
				ShortDescription: message{Text: f.Title},
				FullDescription: message{Text: f.Description},
				Help: message{Text: f.Remediation},
				DefaultConfiguration: configuration{Level: level},
			})
		}
		current.Results = append(current.Results, resultItem{
			RuleID: f.Category,
			Level: level,
			Message: message{Text: f.Title + ": " + f.Description},
		})
	}
	doc.Runs = []run{current}
	return json.MarshalIndent(doc, "", "  ")
}
