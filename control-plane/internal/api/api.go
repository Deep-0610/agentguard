package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Deep-0610/agentguard/control-plane/internal/store"
)

type API struct { store *store.Store; logger *log.Logger }
type principalKey struct{}
type requestIDKey struct{}

func New(s *store.Store,logger *log.Logger)*API{return &API{store:s,logger:logger}}
func (a *API) Handler()http.Handler{
	mux:=http.NewServeMux()
	mux.HandleFunc("GET /healthz",func(w http.ResponseWriter,r *http.Request){writeJSON(w,200,map[string]any{"status":"ok","service":"agentguard-control-plane"})})
	mux.HandleFunc("GET /readyz",a.ready)
	mux.Handle("POST /v1/ingest/scans",a.auth(http.HandlerFunc(a.ingest),"owner","admin","ingest"))
	mux.Handle("GET /v1/dashboard/summary",a.auth(http.HandlerFunc(a.summary),"owner","admin","analyst","viewer"))
	mux.Handle("GET /v1/identities",a.auth(http.HandlerFunc(a.identities),"owner","admin","analyst","viewer"))
	mux.Handle("GET /v1/findings",a.auth(http.HandlerFunc(a.findings),"owner","admin","analyst","viewer"))
	mux.Handle("PATCH /v1/findings/{id}/status",a.auth(http.HandlerFunc(a.updateFinding),"owner","admin","analyst"))
	mux.Handle("GET /v1/audit-events",a.auth(http.HandlerFunc(a.audit),"owner","admin","analyst"))
	mux.Handle("GET /v1/audit-events/verify",a.auth(http.HandlerFunc(a.verifyAudit),"owner","admin"))
	mux.Handle("GET /v1/identities/{id}/events",a.auth(http.HandlerFunc(a.identityEvents),"owner","admin","analyst","viewer"))
	mux.Handle("GET /v1/api-keys",a.auth(http.HandlerFunc(a.listKeys),"owner","admin"))
	mux.Handle("POST /v1/api-keys",a.auth(http.HandlerFunc(a.createKey),"owner","admin"))
	mux.Handle("DELETE /v1/api-keys/{id}",a.auth(http.HandlerFunc(a.revokeKey),"owner","admin"))
	return securityHeaders(requestID(recoverer(a.logger,mux)))
}
func (a *API) auth(next http.Handler,roles ...string)http.Handler{
	allowed:=map[string]bool{};for _,role:=range roles{allowed[role]=true}
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		header:=r.Header.Get("Authorization")
		if !strings.HasPrefix(header,"Bearer ")||len(header)>256{writeError(w,401,"unauthorized","A valid bearer API key is required");return}
		p,err:=a.store.Authenticate(r.Context(),strings.TrimSpace(strings.TrimPrefix(header,"Bearer ")))
		if err!=nil{writeError(w,401,"unauthorized","Invalid or expired API key");return}
		if !allowed[p.Role]{writeError(w,403,"forbidden","This API key does not have permission for this operation");return}
		next.ServeHTTP(w,r.WithContext(context.WithValue(r.Context(),principalKey{},p)))
	})
}
func principal(r *http.Request)store.Principal{return r.Context().Value(principalKey{}).(store.Principal)}
func (a *API) ready(w http.ResponseWriter,r *http.Request){writeJSON(w,200,map[string]any{"status":"ready"})}
func (a *API) ingest(w http.ResponseWriter,r *http.Request){
	var req store.ScanRequest
	raw,err:=readJSON(w,r,&req,8<<20);if err!=nil{writeError(w,400,"invalid_request",err.Error());return}
	if strings.TrimSpace(req.ScanID)==""||len(req.ScanID)>128||strings.TrimSpace(req.Source)==""||len(req.Source)>64{writeError(w,422,"validation_error","scan_id and source are required and must be within documented limits");return}
	if req.CollectedAt.IsZero(){req.CollectedAt=time.Now().UTC()}
	if req.CollectedAt.After(time.Now().Add(5*time.Minute)){writeError(w,422,"validation_error","collected_at cannot be more than five minutes in the future");return}
	if len(req.Assets)>10000||len(req.Findings)>20000{writeError(w,413,"limit_exceeded","A scan may contain at most 10,000 assets and 20,000 findings");return}
	var assessedFindings []store.FindingInput
	for i:=range req.Assets{
		a:=&req.Assets[i]
		if strings.TrimSpace(a.Name)==""||len(a.Name)>512||strings.TrimSpace(a.Source)==""||len(a.Source)>64||len(a.ExternalID)>512{writeError(w,422,"validation_error","Every asset requires a name and source; values must be within documented limits");return}
		if a.Kind==""{a.Kind="unknown"}
		if !oneOf(a.Kind,"agent","mcp_server","oauth_app","service_principal","api_token","service_account","workload_identity","bot","unknown"){writeError(w,422,"validation_error","Unsupported identity kind");return}
		if a.OwnerStatus==""{a.OwnerStatus="UNKNOWN"}
		if !oneOf(a.OwnerStatus,"ACTIVE","SUSPENDED","UNKNOWN"){writeError(w,422,"validation_error","Unsupported owner status");return}
		if a.SecretAgeDays<0||len(a.Scopes)>256{writeError(w,422,"validation_error","Secret age cannot be negative and scopes are limited to 256");return}
		score,generated:=assessAsset(*a)
		a.RiskScore=score
		assessedFindings=append(assessedFindings,generated...)
	}
	req.Findings=append(req.Findings,assessedFindings...)
	for i:=range req.Findings{
		f:=&req.Findings[i]
		if strings.TrimSpace(f.Title)==""||len(f.Title)>512||!oneOf(f.Severity,"critical","high","medium","low","info"){writeError(w,422,"validation_error","Every finding requires a title and a valid severity");return}
		if f.Confidence==""{f.Confidence="medium"}
		if !oneOf(f.Confidence,"low","medium","high"){writeError(w,422,"validation_error","Finding confidence must be low, medium, or high");return}
		if f.Fingerprint==""||len(f.Fingerprint)>256||len(f.RuleID)>128||len(f.Evidence)>4096{writeError(w,422,"validation_error","Finding fingerprint, rule ID or evidence exceeds its limit");return}
	}
	hash:=sha256.Sum256(raw)
	result,err:=a.store.Ingest(r.Context(),principal(r),req,hex.EncodeToString(hash[:]))
	if errors.Is(err,store.ErrDuplicateScan){writeError(w,409,"idempotency_conflict","scan_id was already used with a different payload");return}
	if err!=nil{a.logger.Printf("ingest failed request_id=%s err=%v",requestIDFrom(r),err);writeError(w,500,"ingest_failed","The scan could not be ingested");return}
	writeJSON(w,202,result)
}
func (a *API) summary(w http.ResponseWriter,r *http.Request){v,err:=a.store.Summary(r.Context(),principal(r).TenantID);if err!=nil{writeError(w,500,"query_failed","Unable to load dashboard summary");return};writeJSON(w,200,v)}
func (a *API) identities(w http.ResponseWriter,r *http.Request){limit:=queryLimit(r,100,500);v,err:=a.store.ListIdentities(r.Context(),principal(r).TenantID,limit);if err!=nil{writeError(w,500,"query_failed","Unable to load identity inventory");return};writeJSON(w,200,map[string]any{"items":v,"limit":limit})}
func (a *API) findings(w http.ResponseWriter,r *http.Request){limit:=queryLimit(r,100,500);status:=r.URL.Query().Get("status");if status!=""&&!oneOf(status,"open","acknowledged","accepted-risk","remediated","false-positive"){writeError(w,400,"invalid_filter","Unsupported finding status");return};v,err:=a.store.ListFindings(r.Context(),principal(r).TenantID,status,limit);if err!=nil{writeError(w,500,"query_failed","Unable to load findings");return};writeJSON(w,200,map[string]any{"items":v,"limit":limit})}
func (a *API) updateFinding(w http.ResponseWriter,r *http.Request){
	var body struct{Status string `json:"status"`;Reason string `json:"reason"`}
	if _,err:=readJSON(w,r,&body,16<<10);err!=nil{writeError(w,400,"invalid_request",err.Error());return}
	if len(body.Reason)>1000{writeError(w,422,"validation_error","Reason is too long");return}
	err:=a.store.SetFindingStatus(r.Context(),principal(r),r.PathValue("id"),body.Status,body.Reason)
	if errors.Is(err,store.ErrNotFound){writeError(w,404,"not_found","Finding not found");return}
	if err!=nil{writeError(w,400,"update_failed","Unable to update finding status");return}
	writeJSON(w,200,map[string]any{"status":"updated"})
}
func (a *API) audit(w http.ResponseWriter,r *http.Request){v,err:=a.store.ListAudit(r.Context(),principal(r).TenantID,queryLimit(r,100,500));if err!=nil{writeError(w,500,"query_failed","Unable to load audit events");return};writeJSON(w,200,map[string]any{"items":v})}
func (a *API) verifyAudit(w http.ResponseWriter,r *http.Request){
	result,err:=a.store.VerifyAuditChain(r.Context(),principal(r).TenantID)
	if err!=nil{writeError(w,500,"verification_failed","Unable to verify audit chain");return}
	writeJSON(w,200,result)
}
func (a *API) identityEvents(w http.ResponseWriter,r *http.Request){
	items,err:=a.store.ListIdentityEvents(r.Context(),principal(r).TenantID,r.PathValue("id"),queryLimit(r,100,500))
	if err!=nil{writeError(w,500,"query_failed","Unable to load identity history");return}
	writeJSON(w,200,map[string]any{"items":items})
}
func (a *API) listKeys(w http.ResponseWriter,r *http.Request){v,err:=a.store.ListAPIKeys(r.Context(),principal(r).TenantID);if err!=nil{writeError(w,500,"query_failed","Unable to load API keys");return};writeJSON(w,200,map[string]any{"items":v})}
func (a *API) createKey(w http.ResponseWriter,r *http.Request){
	var body struct{Name string `json:"name"`;Role string `json:"role"`;ExpiresAt string `json:"expires_at,omitempty"`}
	if _,err:=readJSON(w,r,&body,16<<10);err!=nil{writeError(w,400,"invalid_request",err.Error());return}
	var expires *time.Time
	if body.ExpiresAt!=""{
		parsed,err:=time.Parse(time.RFC3339,body.ExpiresAt)
		if err!=nil||!parsed.After(time.Now()){writeError(w,422,"validation_error","expires_at must be a future RFC3339 timestamp");return}
		expires=&parsed
	}
	key,secret,err:=a.store.CreateAPIKey(r.Context(),principal(r),body.Name,body.Role,expires)
	if err!=nil{writeError(w,422,"validation_error",err.Error());return}
	writeJSON(w,201,map[string]any{"key":key,"secret":secret,"warning":"Copy this secret now. It cannot be retrieved again."})
}
func (a *API) revokeKey(w http.ResponseWriter,r *http.Request){
	err:=a.store.RevokeAPIKey(r.Context(),principal(r),r.PathValue("id"))
	if errors.Is(err,store.ErrNotFound){writeError(w,404,"not_found","API key not found");return}
	if err!=nil{writeError(w,500,"revoke_failed","Unable to revoke API key");return}
	w.WriteHeader(http.StatusNoContent)
}

func readJSON(w http.ResponseWriter,r *http.Request,dst any,max int64)([]byte,error){
	if r.Header.Get("Content-Type")!=""&&!strings.HasPrefix(r.Header.Get("Content-Type"),"application/json"){return nil,fmt.Errorf("Content-Type must be application/json")}
	r.Body=http.MaxBytesReader(w,r.Body,max);defer r.Body.Close()
	raw,err:=io.ReadAll(r.Body);if err!=nil{return nil,fmt.Errorf("request body is invalid or exceeds %d bytes",max)}
	decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields()
	if err=decoder.Decode(dst);err!=nil{return nil,fmt.Errorf("invalid JSON: %w",err)}
	if decoder.Decode(&struct{}{})!=io.EOF{return nil,fmt.Errorf("request must contain exactly one JSON value")}
	return raw,nil
}
func writeJSON(w http.ResponseWriter,status int,v any){w.Header().Set("Content-Type","application/json");w.WriteHeader(status);_ = json.NewEncoder(w).Encode(v)}
func writeError(w http.ResponseWriter,status int,code,message string){writeJSON(w,status,map[string]any{"error":map[string]string{"code":code,"message":message}})}
func queryLimit(r *http.Request,def,max int)int{v:=r.URL.Query().Get("limit");if v==""{return def};n,err:=strconv.Atoi(v);if err!=nil||n<1{return def};if n>max{return max};return n}
func oneOf(v string,values ...string)bool{for _,x:=range values{if v==x{return true}};return false}
func requestID(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
	id:=r.Header.Get("X-Request-ID");if len(id)>64||strings.ContainsAny(id,"\r\n"){id=""};if id==""{id=fmt.Sprintf("%d",time.Now().UnixNano())}
	w.Header().Set("X-Request-ID",id);next.ServeHTTP(w,r.WithContext(context.WithValue(r.Context(),requestIDKey{},id)))
})}
func requestIDFrom(r *http.Request)string{v,_:=r.Context().Value(requestIDKey{}).(string);return v}
func recoverer(logger *log.Logger,next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
	defer func(){if recover()!=nil{logger.Printf("panic recovered request_id=%s",requestIDFrom(r));writeError(w,500,"internal_error","Unexpected server error")}}()
	next.ServeHTTP(w,r)
})}
func securityHeaders(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
	w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("Cache-Control","no-store");w.Header().Set("Referrer-Policy","no-referrer");w.Header().Set("X-Frame-Options","DENY")
	next.ServeHTTP(w,r)
})}
