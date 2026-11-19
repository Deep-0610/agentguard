package syncer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Deep-0610/agentguard/internal/model"
)

func TestBuildPayloadDoesNotIncludeServerCredentials(t *testing.T){
	servers:=[]model.Server{{Name:"docs",Config:"/home/user/mcp.json",Command:"node",Args:[]string{"--token","super-secret"},Env:map[string]string{"TOKEN":"secret-value"},URL:"https://user:pass@example.test"}}
	raw,err:=BuildPayload(servers,nil,"0.1.0",time.Now());if err!=nil{t.Fatal(err)}
	for _,secret:=range []string{"super-secret","secret-value","user:pass","/home/user"}{if strings.Contains(string(raw),secret){t.Fatalf("sync payload leaked sensitive config value %q: %s",secret,raw)}}
}
func TestSyncUsesBearerAndMapsResponse(t *testing.T){
	server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.URL.Path!="/v1/ingest/scans"{t.Fatalf("unexpected path %s",r.URL.Path)}
		if r.Header.Get("Authorization")!="Bearer ag_live_test"{t.Fatal("missing bearer authorization")}
		var body map[string]any
		if err:=json.NewDecoder(r.Body).Decode(&body);err!=nil{t.Fatal(err)}
		if body["source"]!="agentguard-cli"{t.Fatalf("unexpected source: %#v",body["source"])}
		w.Header().Set("Content-Type","application/json")
		_,_=w.Write([]byte(`{"scan_id":"scan-1","assets_upserted":1,"findings_upserted":2,"duplicate":false}`))
	}))
	defer server.Close()
	result,err:=Sync(context.Background(),server.URL,"ag_live_test",[]model.Server{{Name:"docs",Config:"mcp.json"}},nil,"0.1.0")
	if err!=nil{t.Fatal(err)}
	if result.ScanID!="scan-1"||result.AssetsUpserted!=1||result.FindingsUpserted!=2{t.Fatalf("unexpected response: %+v",result)}
}
func TestIngestURLRequiresTLSOutsideLoopback(t *testing.T){
	if _,err:=ingestURL("http://example.com");err==nil{t.Fatal("expected non-loopback HTTP to be rejected")}
	if _,err:=ingestURL("https://user:password@example.com");err==nil{t.Fatal("expected URL userinfo to be rejected")}
	if _,err:=ingestURL("http://localhost:8080");err!=nil{t.Fatalf("localhost HTTP should be allowed for local development: %v",err)}
}
