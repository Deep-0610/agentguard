package report

import (
	"encoding/json"
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
		Transport: "transportsecretvalue",
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
		for _, forbidden := range []string{secret, "supersecretvalue", "privatecredentialvalue", "transportsecretvalue"} {
			if strings.Contains(string(output), forbidden) {
				t.Fatalf("%s report leaked sensitive value %q", format, forbidden)
			}
		}
	}
}

func TestSARIFDefinesRulesReferencedByResults(t *testing.T) {
	findings := []model.Finding{
		{ID:"1",Category:"secret-exposure",Severity:"critical",Title:"Secret exposure",Description:"Sensitive value detected",Remediation:"Rotate the credential"},
		{ID:"2",Category:"transport-security",Severity:"high",Title:"HTTP endpoint",Description:"Endpoint is not encrypted",Remediation:"Use HTTPS"},
	}
	output,err:=Render("sarif",nil,findings)
	if err!=nil { t.Fatal(err) }
	var document struct {
		Version string `json:"version"`
		Runs []struct {
			Tool struct { Driver struct {
				Rules []struct { ID string `json:"id"` } `json:"rules"`
			} `json:"driver"` } `json:"tool"`
			Results []struct { RuleID string `json:"ruleId"` } `json:"results"`
		} `json:"runs"`
	}
	if err:=json.Unmarshal(output,&document); err!=nil { t.Fatal(err) }
	if document.Version!="2.1.0" || len(document.Runs)!=1 { t.Fatalf("unexpected SARIF envelope: %#v",document) }
	rules:=map[string]bool{}
	for _,rule:=range document.Runs[0].Tool.Driver.Rules { rules[rule.ID]=true }
	for _,result:=range document.Runs[0].Results {
		if !rules[result.RuleID] { t.Fatalf("result references undefined rule %q",result.RuleID) }
	}
}

func TestHTMLReportEscapesUntrustedLabels(t *testing.T) {
	server:=model.Server{Name:`<script>alert("x")</script>`,Config:"mcp.json"}
	output,err:=Render("html",[]model.Server{server},nil)
	if err!=nil { t.Fatal(err) }
	if strings.Contains(string(output),`<script>alert`) { t.Fatal("untrusted label was emitted as executable HTML") }
}
