package api

import (
	"strings"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
