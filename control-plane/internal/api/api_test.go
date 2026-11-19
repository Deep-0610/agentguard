package api

import (
	"strings"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Deep-0610/agentguard/control-plane/internal/store"
)

func TestReadJSONRejectsUnknownFields(t *testing.T) {
	req:=httptest.NewRequest(http.MethodPost,"/",strings.NewReader("{\"known\":\"ok\",\"unexpected\":\"no\"}"))
	req.Header.Set("Content-Type","application/json")
	var dst struct{Known string `json:"known"`}
	_,err:=readJSON(httptest.NewRecorder(),req,&dst,1024)
	if err==nil { t.Fatal("expected unknown field to be rejected") }
}
func TestReadJSONRejectsTrailingValues(t *testing.T) {
	req:=httptest.NewRequest(http.MethodPost,"/",strings.NewReader("{\"known\":\"ok\"} {\"second\":true}"))
	req.Header.Set("Content-Type","application/json")
	var dst map[string]any
	_,err:=readJSON(httptest.NewRecorder(),req,&dst,1024)
	if err==nil { t.Fatal("expected trailing JSON value to be rejected") }
}
func TestReadJSONRejectsOversizedBody(t *testing.T) {
	payload:="{\"known\":\""+strings.Repeat("x",100)+"\"}"
	req:=httptest.NewRequest(http.MethodPost,"/",strings.NewReader(payload))
	req.Header.Set("Content-Type","application/json")
	var dst map[string]any
	_,err:=readJSON(httptest.NewRecorder(),req,&dst,16)
	if err==nil { t.Fatal("expected oversized body to be rejected") }
}
func TestSecurityHeaders(t *testing.T) {
	h:=securityHeaders(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){writeJSON(w,200,map[string]string{"ok":"yes"})}))
	rr:=httptest.NewRecorder()
	h.ServeHTTP(rr,httptest.NewRequest(http.MethodGet,"/",nil))
	for _,key:=range []string{"X-Content-Type-Options","Cache-Control","Referrer-Policy","X-Frame-Options"} {
		if rr.Header().Get(key)=="" { t.Fatalf("missing %s",key) }
	}
	var body map[string]string
	if err:=json.Unmarshal(rr.Body.Bytes(),&body);err!=nil||body["ok"]!="yes" { t.Fatalf("unexpected response: %s",rr.Body.String()) }
}
func TestQueryLimitIsBounded(t *testing.T) {
	req:=httptest.NewRequest(http.MethodGet,"/?limit=99999",nil)
	if got:=queryLimit(req,100,500);got!=500 { t.Fatalf("expected limit cap 500, got %d",got) }
}

func TestAssessAssetFlagsPrivilegedUnknownOwner(t *testing.T) {
	asset:=store.AssetInput{ExternalID:"bot-1",Source:"entra",Kind:"service_principal",Name:"deploy-bot",OwnerStatus:"UNKNOWN",Scopes:[]string{"Repository.Write","Directory.ReadWrite.All"}}
	score,findings:=assessAsset(asset)
	if score<95 { t.Fatalf("expected critical risk score, got %d",score) }
	if len(findings)==0||findings[0].Severity!="critical" { t.Fatalf("expected critical finding, got %#v",findings) }
}
func TestAssessAssetFlagsToxicPermissionCombination(t *testing.T) {
	asset:=store.AssetInput{ExternalID:"agent-2",Source:"mcp",Kind:"agent",Name:"ops-agent",OwnerStatus:"ACTIVE",Scopes:[]string{"Mail.Send","Database.Read"}}
	score,findings:=assessAsset(asset)
	if score!=98||len(findings)!=1||findings[0].RuleID!="nhi.toxic-permission-combination" { t.Fatalf("unexpected toxic-combination assessment: score=%d findings=%#v",score,findings) }
}
func TestAssessAssetFlagsStaleAPIToken(t *testing.T) {
	asset:=store.AssetInput{ExternalID:"token-3",Source:"okta",Kind:"api_token",Name:"legacy-token",OwnerStatus:"ACTIVE",SecretAgeDays:120}
	score,findings:=assessAsset(asset)
	if score!=55||len(findings)!=1||findings[0].RuleID!="nhi.stale-api-token" { t.Fatalf("unexpected stale-token assessment: score=%d findings=%#v",score,findings) }
}

func TestRedactUntrustedRemovesCredentialValues(t *testing.T) {
	input:="token=supersecretvalue https://alice:verysecret@example.test/mcp ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	got:=redactUntrusted(input)
	for _,secret:=range []string{"supersecretvalue","verysecret","ghp_abcdefghijklmnopqrstuvwxyz1234567890"} {
		if strings.Contains(got,secret) { t.Fatalf("credential survived redaction: %q",got) }
	}
}
func TestRedactUntrustedRemovesCompletePrivateKey(t *testing.T) {
	input:="-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----"
	got:=redactUntrusted(input)
	if strings.Contains(got,"private-material") { t.Fatalf("private key body survived redaction: %q",got) }
}

func TestRequestIDRejectsControlCharacters(t *testing.T) {
	handler:=requestID(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){}))
	req:=httptest.NewRequest(http.MethodGet,"/",nil)
	req.Header.Set("X-Request-ID","valid\x1b[31m-injected")
	rr:=httptest.NewRecorder()
	handler.ServeHTTP(rr,req)
	got:=rr.Header().Get("X-Request-ID")
	if strings.ContainsAny(got,"\x1b\r\n") { t.Fatalf("unsafe request ID survived: %q",got) }
}
