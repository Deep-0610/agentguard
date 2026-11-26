package syncer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/Deep-0610/agentguard/internal/model"
)

type asset struct {
	ExternalID string `json:"external_id"`
	Source string `json:"source"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	Environment string `json:"environment"`
}
type finding struct {
	Fingerprint string `json:"fingerprint"`
	RuleID string `json:"rule_id"`
	Severity string `json:"severity"`
	Confidence string `json:"confidence"`
	Category string `json:"category"`
	Title string `json:"title"`
	Description string `json:"description"`
	Resource string `json:"resource"`
	Location string `json:"location"`
	Evidence string `json:"evidence"`
	Remediation string `json:"remediation"`
}
type request struct {
	ScanID string `json:"scan_id"`
	Source string `json:"source"`
	ScannerVersion string `json:"scanner_version"`
	CollectedAt time.Time `json:"collected_at"`
	Assets []asset `json:"assets"`
	Findings []finding `json:"findings"`
}
type Result struct {
	ScanID string `json:"scan_id"`
	AssetsUpserted int `json:"assets_upserted"`
	FindingsUpserted int `json:"findings_upserted"`
	Duplicate bool `json:"duplicate"`
}

func BuildPayload(servers []model.Server,findings []model.Finding,version string,now time.Time)([]byte,error){
	random:=make([]byte,16);if _,err:=rand.Read(random);err!=nil{return nil,err}
	payload:=request{ScanID:hex.EncodeToString(random),Source:"agentguard-cli",ScannerVersion:version,CollectedAt:now.UTC(),Assets:[]asset{},Findings:[]finding{}}
	for _,server:=range servers{
		identity:=sha256.Sum256([]byte(filepath.Base(server.Config)+":"+server.Name))
		payload.Assets=append(payload.Assets,asset{ExternalID:"mcp:"+hex.EncodeToString(identity[:]),Source:"mcp",Kind:"mcp_server",Name:server.Name,Environment:"unknown"})
	}
	for _,item:=range findings{
		payload.Findings=append(payload.Findings,finding{Fingerprint:item.ID,RuleID:item.Category,Severity:item.Severity,Confidence:"medium",Category:item.Category,Title:item.Title,Description:item.Description,Resource:item.Resource,Location:item.Location,Evidence:item.Evidence,Remediation:item.Remediation})
	}
	return json.Marshal(payload)
}

func Sync(ctx context.Context,baseURL,token string,servers []model.Server,findings []model.Finding,version string)(Result,error){
	if strings.TrimSpace(token)==""{return Result{},fmt.Errorf("API key is required; set AGENTGUARD_API_KEY or pass --token")}
	endpoint,err:=ingestURL(baseURL);if err!=nil{return Result{},err}
	body,err:=BuildPayload(servers,findings,version,time.Now());if err!=nil{return Result{},err}
	req,err:=http.NewRequestWithContext(ctx,http.MethodPost,endpoint,bytes.NewReader(body));if err!=nil{return Result{},err}
	req.Header.Set("Authorization","Bearer "+token)
	req.Header.Set("Content-Type","application/json")
	req.Header.Set("Accept","application/json")
	client:=&http.Client{Timeout:20*time.Second,CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}}
	resp,err:=client.Do(req);if err!=nil{return Result{},fmt.Errorf("send scan to AgentGuard control plane: %w",err)}
	defer resp.Body.Close()
	raw,err:=io.ReadAll(io.LimitReader(resp.Body,64<<10));if err!=nil{return Result{},err}
	if resp.StatusCode<200||resp.StatusCode>=300{return Result{},fmt.Errorf("control plane returned HTTP %d: %s",resp.StatusCode,strings.TrimSpace(string(raw)))}
	var result Result
	if err=json.Unmarshal(raw,&result);err!=nil{return Result{},fmt.Errorf("invalid control-plane response: %w",err)}
	return result,nil
}

func ingestURL(base string)(string,error){
	parsed,err:=url.Parse(strings.TrimSpace(base));if err!=nil{return "",fmt.Errorf("invalid control-plane URL: %w",err)}
	if parsed.User!=nil||parsed.RawQuery!=""||parsed.Fragment!=""{return "",fmt.Errorf("control-plane URL must not include userinfo, query parameters, or a fragment")}
	if parsed.Scheme!="https"&&!(parsed.Scheme=="http"&&isLoopback(parsed.Hostname())){return "",fmt.Errorf("control-plane URL must use HTTPS (HTTP is allowed only for localhost)")}
	if parsed.Hostname()==""{return "",fmt.Errorf("control-plane URL must include a host")}
	return strings.TrimRight(parsed.String(),"/")+"/v1/ingest/scans",nil
}
func isLoopback(host string)bool{
	if strings.EqualFold(host,"localhost"){return true}
	ip:=net.ParseIP(host);return ip!=nil&&ip.IsLoopback()
}
