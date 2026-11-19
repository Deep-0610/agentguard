package scanner

import (
	"strings"
	"testing"

	"github.com/Deep-0610/agentguard/internal/model"
)

func TestAdversarialInputsAreRedactedAndDetected(t *testing.T) {
	secret := "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	cases := []struct {
		name string
		server model.Server
		wantLocation string
	}{
		{"split token flag", model.Server{Name:"demo",Config:"mcp.json",Args:[]string{"--token",secret}}, "args[1]"},
		{"inline token flag", model.Server{Name:"demo",Config:"mcp.json",Args:[]string{"--token="+secret}}, "args[0]"},
		{"URL username", model.Server{Name:"demo",Config:"mcp.json",URL:"https://"+secret+"@example.test/mcp"}, "url.userinfo"},
		{"URL fragment", model.Server{Name:"demo",Config:"mcp.json",URL:"https://example.test/mcp#access_token="+secret}, "url.fragment"},
		{"tool declaration", model.Server{Name:"demo",Config:"mcp.json",Tools:[]map[string]any{{"description":secret}}}, "tools[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name,func(t *testing.T){
			findings:=Analyze([]model.Server{tc.server})
			found:=false
			for _,f:=range findings {
				if f.Location==tc.wantLocation {
					found=true
					if strings.Contains(f.Evidence,secret) || f.Evidence!="[REDACTED]" {
						t.Fatalf("sensitive value not fully redacted: %q",f.Evidence)
					}
				}
			}
			if !found { t.Fatalf("expected finding at %s; got %#v",tc.wantLocation,findings) }
		})
	}
}

func TestFindingResourceDoesNotEchoSecretServerName(t *testing.T) {
	secret:="ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	findings:=Analyze([]model.Server{{Name:secret,Config:"/tmp/"+secret+"/mcp.json",Env:map[string]string{"TOKEN":"value"}}})
	for _,f:=range findings {
		if strings.Contains(f.Resource,secret) { t.Fatalf("secret leaked through resource: %q",f.Resource) }
	}
}

func TestRedactDoesNotRetainPrefixOrSuffix(t *testing.T) {
	value:="prefix-ghp_abcdefghijklmnopqrstuvwxyz1234567890-suffix"
	if got:=redact(value); got!="[REDACTED]" { t.Fatalf("expected complete redaction, got %q",got) }
}
