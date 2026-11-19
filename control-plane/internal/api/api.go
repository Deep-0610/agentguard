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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Deep-0610/agentguard/control-plane/internal/store"
	"github.com/Deep-0610/agentguard/control-plane/internal/policy"
)

type API struct { store *store.Store; logger *log.Logger; evaluator *policy.Evaluator }
type principalKey struct{}
type requestIDKey struct{}

func New(s *store.Store,logger *log.Logger)*API{return &API{store:s,logger:logger,evaluator:policy.New(os.Getenv("AG_OPA_URL"))}}
func (a *API) Handler()http.Handler{
	mux:=http.NewServeMux()
	mux.HandleFunc("GET /healthz",func(w http.ResponseWriter,r *http.Request){writeJSON(w,200,map[string]any{"status":"ok","service":"agentguard-control-plane"})})
	mux.HandleFunc("GET /readyz",a.ready)
	mux.Handle("POST /v1/ingest/scans",a.auth(http.HandlerFunc(a.ingest),"owner","admin","ingest"))
	mux.Handle("POST /v1/policies/evaluate",a.auth(http.HandlerFunc(a.evaluatePolicy),"owner","admin","analyst"))
	mux.Handle("GET /v1/tool-baselines",a.auth(http.HandlerFunc(a.listToolBaselines),"owner","admin","analyst","viewer"))
	mux.Handle("PUT /v1/tool-baselines/{name}",a.auth(http.HandlerFunc(a.setToolBaseline),"owner","admin"))
	mux.Handle("GET /v1/dashboard/summary",a.auth(http.HandlerFunc(a.summary),"owner","admin","analyst","viewer"))
	mux.Handle("GET /v1/identities",a.auth(http.HandlerFunc(a.identities),"owner","admin","analyst","viewer"))
	mux.Handle("GET /v1/relationships",a.auth(http.HandlerFunc(a.relationships),"owner","admin","analyst","viewer"))
	mux.Handle("GET /v1/findings",a.auth(http.HandlerFunc(a.findings),"owner","admin","analyst","viewer"))
	mux.Handle("PATCH /v1/findings/{id}/status",a.auth(http.HandlerFunc(a.updateFinding),"owner","admin","analyst"))
	mux.Handle("GET /v1/audit-events",a.auth(http.HandlerFunc(a.audit),"owner","admin","analyst"))
	mux.Handle("GET /v1/audit-events/verify",a.auth(http.HandlerFunc(a.verifyAudit),"owner","admin"))
	mux.Handle("GET /v1/identities/{id}/events",a.auth(http.HandlerFunc(a.identityEvents),"owner","admin","analyst","viewer"))
	mux.Handle("GET /v1/api-keys",a.auth(http.HandlerFunc(a.listKeys),"owner","admin"))
	mux.Handle("POST /v1/api-keys",a.auth(http.HandlerFunc(a.createKey),"owner","admin"))
	mux.Handle("DELETE /v1/api-keys/{id}",a.auth(http.HandlerFunc(a.revokeKey),"owner","admin"))
	mux.Handle("GET /v1/mfa/status",a.auth(http.HandlerFunc(a.mfaStatus),"owner","admin"))
	mux.Handle("POST /v1/mfa/totp/enroll",a.auth(http.HandlerFunc(a.enrollTOTP),"owner","admin"))
	mux.Handle("POST /v1/mfa/totp/verify",a.auth(http.HandlerFunc(a.verifyTOTP),"owner","admin"))
	return securityHeaders(requestID(recoverer(a.logger,mux)))
}
func (a *API) auth(next http.Handler,roles ...string)http.Handler{
	allowed:=map[string]bool{};for _,role:=range roles{allowed[role]=true}
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		header:=r.Header.Get("Authorization")
		if !strings.HasPrefix(header,"Bearer ")||len(header)>256{writeError(w,401,"unauthorized","A valid bearer API key is required");return}
		p,err:=a.store.Authenticate(r.Context(),strings.TrimSpace(strings.TrimPrefix(header,"Bearer ")))
		if err!=nil{writeError(w,401,"unauthorized","Invalid or expired API key");return}
		p.RequestID=requestIDFrom(r)
		if !allowed[p.Role]{writeError(w,403,"forbidden","This API key does not have permission for this operation");return}
		next.ServeHTTP(w,r.WithContext(context.WithValue(r.Context(),principalKey{},p)))
	})
}
func principal(r *http.Request)store.Principal{return r.Context().Value(principalKey{}).(store.Principal)}
func (a *API) ready(w http.ResponseWriter,r *http.Request){if err:=a.store.Ping(r.Context());err!=nil{writeError(w,503,"not_ready","Database is unavailable");return};if err:=a.evaluator.Ready(r.Context());err!=nil{writeError(w,503,"not_ready","Policy service is unavailable");return};writeJSON(w,200,map[string]any{"status":"ready"})}
func (a *API) ingest(w http.ResponseWriter,r *http.Request){
	var req store.ScanRequest
	raw,err:=readJSON(w,r,&req,8<<20);if err!=nil{writeError(w,400,"invalid_request",err.Error());return}
	if strings.TrimSpace(req.ScanID)==""||len(req.ScanID)>128||strings.TrimSpace(req.Source)==""||len(req.Source)>64||len(req.ScannerVersion)>80{writeError(w,422,"validation_error","scan_id and source are required and must be within documented limits");return}
	req.ScanID=redactUntrusted(req.ScanID);req.Source=redactUntrusted(req.Source);req.ScannerVersion=redactUntrusted(req.ScannerVersion)
	if req.CollectedAt.IsZero(){req.CollectedAt=time.Now().UTC()}
	if req.CollectedAt.After(time.Now().Add(5*time.Minute)){writeError(w,422,"validation_error","collected_at cannot be more than five minutes in the future");return}
	if len(req.Assets)>10000||len(req.Findings)>20000||len(req.Relationships)>20000{writeError(w,413,"limit_exceeded","A scan may contain at most 10,000 assets, 20,000 findings and 20,000 relationships");return}
	var assessedFindings []store.FindingInput
	for i:=range req.Assets{
		a:=&req.Assets[i]
		if strings.TrimSpace(a.Name)==""||len(a.Name)>512||strings.TrimSpace(a.Source)==""||len(a.Source)>64||len(a.ExternalID)>512||len(a.OwnerEmail)>320||len(a.Environment)>80{writeError(w,422,"validation_error","Every asset requires a name and source; values must be within documented limits");return}
		if a.Kind==""{a.Kind="unknown"}
		if !oneOf(a.Kind,"agent","mcp_server","oauth_app","service_principal","api_token","service_account","workload_identity","bot","unknown"){writeError(w,422,"validation_error","Unsupported identity kind");return}
		if a.OwnerStatus==""{a.OwnerStatus="UNKNOWN"}
		if !oneOf(a.OwnerStatus,"ACTIVE","SUSPENDED","UNKNOWN"){writeError(w,422,"validation_error","Unsupported owner status");return}
		if a.SecretAgeDays<0||len(a.Scopes)>256{writeError(w,422,"validation_error","Secret age cannot be negative and scopes are limited to 256");return}
		a.Name=redactUntrusted(a.Name);a.Source=redactUntrusted(a.Source);a.ExternalID=redactUntrusted(a.ExternalID);a.OwnerEmail=redactUntrusted(a.OwnerEmail);a.Environment=redactUntrusted(a.Environment)
		for j:=range a.Scopes{if len(a.Scopes[j])>256{writeError(w,422,"validation_error","Each scope is limited to 256 characters");return};a.Scopes[j]=redactUntrusted(a.Scopes[j])}
		score,generated:=assessAsset(*a)
		a.RiskScore=score
		assessedFindings=append(assessedFindings,generated...)
	}
	req.Findings=append(req.Findings,assessedFindings...)
	if len(req.Findings)>20000{writeError(w,413,"limit_exceeded","Generated risk findings exceed the 20,000 finding limit");return}
	for i:=range req.Relationships{rel:=&req.Relationships[i];if rel.FromSource==""||rel.ToSource==""||rel.FromExternalID==""||rel.ToExternalID==""||len(rel.FromSource)>64||len(rel.ToSource)>64||len(rel.FromExternalID)>512||len(rel.ToExternalID)>512||len(rel.Evidence)>1024||!oneOf(rel.Type,"uses","accesses","delegates_to","created_by","connected_to","owns"){writeError(w,422,"validation_error","Relationship endpoints, type or evidence are invalid");return};rel.FromSource=redactUntrusted(rel.FromSource);rel.FromExternalID=redactUntrusted(rel.FromExternalID);rel.ToSource=redactUntrusted(rel.ToSource);rel.ToExternalID=redactUntrusted(rel.ToExternalID);rel.Evidence=redactUntrusted(rel.Evidence)}
	for i:=range req.Findings{
		f:=&req.Findings[i]
		if strings.TrimSpace(f.Title)==""||len(f.Title)>512||!oneOf(f.Severity,"critical","high","medium","low","info"){writeError(w,422,"validation_error","Every finding requires a title and a valid severity");return}
		if f.Confidence==""{f.Confidence="medium"}
		if !oneOf(f.Confidence,"low","medium","high"){writeError(w,422,"validation_error","Finding confidence must be low, medium, or high");return}
		if f.Fingerprint==""||len(f.Fingerprint)>256||len(f.RuleID)>128||len(f.Category)>128||len(f.Description)>4000||len(f.Resource)>512||len(f.Location)>512||len(f.Evidence)>4096||len(f.Remediation)>4000{writeError(w,422,"validation_error","Finding fields exceed their documented limits");return}
		f.Fingerprint=redactUntrusted(f.Fingerprint);f.RuleID=redactUntrusted(f.RuleID);f.Title=redactUntrusted(f.Title);f.Description=redactUntrusted(f.Description);f.Resource=redactUntrusted(f.Resource);f.Location=redactUntrusted(f.Location);f.Evidence=redactUntrusted(f.Evidence);f.Remediation=redactUntrusted(f.Remediation);f.Category=redactUntrusted(f.Category)
	}
	hash:=sha256.Sum256(raw)
	result,err:=a.store.Ingest(r.Context(),principal(r),req,hex.EncodeToString(hash[:]))
	if errors.Is(err,store.ErrDuplicateScan){writeError(w,409,"idempotency_conflict","scan_id was already used with a different payload");return}
	if err!=nil{a.logger.Printf("ingest failed request_id=%s err=%v",requestIDFrom(r),err);writeError(w,500,"ingest_failed","The scan could not be ingested");return}
	writeJSON(w,202,result)
}
func (a *API) evaluatePolicy(w http.ResponseWriter,r *http.Request){
	var body struct{
		Action string `json:"action"`
		ResourceType string `json:"resource_type"`
		ResourceID string `json:"resource_id"`
		Tool struct{
			Name string `json:"name"`
			SchemaHash string `json:"schema_hash"`
		} `json:"tool"`
	}
	if _,err:=readJSON(w,r,&body,32<<10);err!=nil{writeError(w,400,"invalid_request",err.Error());return}
	if !oneOf(body.Action,"inventory.read","tool.invoke"){writeError(w,422,"validation_error","Unsupported policy action");return}
	if len(body.ResourceType)>80||len(body.ResourceID)>256||len(body.Tool.Name)>256{writeError(w,422,"validation_error","Policy resource or tool fields exceed limits");return}
	p:=principal(r)
	risk:="";approvedSchemaHash:="";approvalRequired:=false
	if body.Action=="tool.invoke"{
		if strings.TrimSpace(body.Tool.Name)==""||!validSchemaHash(body.Tool.SchemaHash){writeError(w,422,"validation_error","Tool name and lowercase SHA-256 schema_hash are required");return}
		body.Tool.Name=redactUntrusted(body.Tool.Name)
		baseline,err:=a.store.GetToolBaseline(r.Context(),p.TenantID,body.Tool.Name)
		if errors.Is(err,store.ErrNotFound){risk="critical"}else if err!=nil{writeError(w,500,"baseline_lookup_failed","Unable to load approved tool baseline");return}else{risk=baseline.Risk;approvedSchemaHash=baseline.ApprovedSchemaHash}
		approvalRequired=risk=="medium"||risk=="high"||risk=="critical"
	}
	input:=map[string]any{
		"action":body.Action,
		"actor":map[string]any{"tenant_id":p.TenantID,"id":p.KeyID,"role":p.Role},
		"resource":map[string]any{"tenant_id":p.TenantID,"type":body.ResourceType,"id":body.ResourceID},
		"tool":map[string]any{"name":body.Tool.Name,"risk":risk,"schema_hash":body.Tool.SchemaHash,"approved_schema_hash":approvedSchemaHash},
		"approval":map[string]any{"required":approvalRequired},
	}
	decision,err:=a.evaluator.Evaluate(r.Context(),input)
	if err!=nil{writeError(w,503,"policy_unavailable","Policy evaluation unavailable; request was not authorized");return}
	if err=a.store.RecordPolicyDecision(r.Context(),p,body.Action,decision.Effect,decision.RuleID,decision.Reason);err!=nil{writeError(w,500,"audit_failed","Policy decision could not be durably audited");return}
	writeJSON(w,200,decision)
}
func (a *API) listToolBaselines(w http.ResponseWriter,r *http.Request){
	items,err:=a.store.ListToolBaselines(r.Context(),principal(r).TenantID,queryLimit(r,100,500))
	if err!=nil{writeError(w,500,"query_failed","Unable to load approved tool baselines");return}
	writeJSON(w,200,map[string]any{"items":items})
}
func (a *API) setToolBaseline(w http.ResponseWriter,r *http.Request){
	var body struct{
		ApprovedSchemaHash string `json:"approved_schema_hash"`
		Risk string `json:"risk"`
	}
	if _,err:=readJSON(w,r,&body,16<<10);err!=nil{writeError(w,400,"invalid_request",err.Error());return}
	toolName:=redactUntrusted(r.PathValue("name"))
	baseline,err:=a.store.SetToolBaseline(r.Context(),principal(r),toolName,body.ApprovedSchemaHash,body.Risk)
	if err!=nil{writeError(w,422,"validation_error",err.Error());return}
	writeJSON(w,200,map[string]any{"baseline":baseline})
}
func (a *API) summary(w http.ResponseWriter,r *http.Request){v,err:=a.store.Summary(r.Context(),principal(r).TenantID);if err!=nil{writeError(w,500,"query_failed","Unable to load dashboard summary");return};writeJSON(w,200,v)}
func (a *API) identities(w http.ResponseWriter,r *http.Request){limit:=queryLimit(r,100,500);v,err:=a.store.ListIdentities(r.Context(),principal(r).TenantID,limit);if err!=nil{writeError(w,500,"query_failed","Unable to load identity inventory");return};writeJSON(w,200,map[string]any{"items":v,"limit":limit})}
func (a *API) relationships(w http.ResponseWriter,r *http.Request){
	items,err:=a.store.ListRelationships(r.Context(),principal(r).TenantID,queryLimit(r,200,1000))
	if err!=nil{writeError(w,500,"query_failed","Unable to load identity graph");return}
	writeJSON(w,200,map[string]any{"items":items})
}
func (a *API) findings(w http.ResponseWriter,r *http.Request){limit:=queryLimit(r,100,500);status:=r.URL.Query().Get("status");if status!=""&&!oneOf(status,"open","acknowledged","accepted-risk","remediated","false-positive"){writeError(w,400,"invalid_filter","Unsupported finding status");return};v,err:=a.store.ListFindings(r.Context(),principal(r).TenantID,status,limit);if err!=nil{writeError(w,500,"query_failed","Unable to load findings");return};writeJSON(w,200,map[string]any{"items":v,"limit":limit})}
func (a *API) updateFinding(w http.ResponseWriter,r *http.Request){
	var body struct{Status string `json:"status"`;Reason string `json:"reason"`}
	if _,err:=readJSON(w,r,&body,16<<10);err!=nil{writeError(w,400,"invalid_request",err.Error());return}
	body.Reason=redactUntrusted(body.Reason)
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
	body.Name=redactUntrusted(body.Name)
	key,secret,err:=a.store.CreateAPIKey(r.Context(),principal(r),body.Name,body.Role,expires)
	if err!=nil{writeError(w,422,"validation_error",err.Error());return}
	writeJSON(w,201,map[string]any{"key":key,"secret":secret,"warning":"Copy this secret now. It cannot be retrieved again."})
}
func (a *API) mfaStatus(w http.ResponseWriter,r *http.Request){
	enabled,err:=a.store.MFAStatus(r.Context(),principal(r))
	if err!=nil{writeError(w,500,"mfa_status_failed","Unable to load MFA status");return}
	writeJSON(w,200,map[string]any{"totp_enabled":enabled})
}
func (a *API) enrollTOTP(w http.ResponseWriter,r *http.Request){
	p:=principal(r)
	secret,err:=a.store.BeginTOTPEnrollment(r.Context(),p)
	if err!=nil{writeError(w,409,"mfa_enrollment_unavailable",err.Error());return}
	writeJSON(w,201,map[string]any{
		"secret":secret,
		"otpauth_url":store.TOTPProvisioningURI("AgentGuard",p.Name,secret),
		"warning":"This enrollment secret is shown once. Add it to an authenticator app, then verify a current six-digit code.",
	})
}
func (a *API) verifyTOTP(w http.ResponseWriter,r *http.Request){
	var body struct{Code string `json:"code"`}
	if _,err:=readJSON(w,r,&body,8<<10);err!=nil{writeError(w,400,"invalid_request",err.Error());return}
	err:=a.store.ConfirmTOTP(r.Context(),principal(r),body.Code)
	if errors.Is(err,store.ErrMFAInvalid){writeError(w,403,"mfa_invalid","The TOTP code is invalid or already used");return}
	if errors.Is(err,store.ErrMFALocked){writeError(w,429,"mfa_locked","MFA verification is temporarily locked");return}
	if errors.Is(err,store.ErrMFARequired){writeError(w,409,"mfa_not_enrolled","Start TOTP enrollment before verification");return}
	if err!=nil{writeError(w,409,"mfa_verification_failed",err.Error());return}
	writeJSON(w,200,map[string]any{"totp_enabled":true})
}
func (a *API) revokeKey(w http.ResponseWriter,r *http.Request){
	err:=a.store.RevokeAPIKey(r.Context(),principal(r),r.PathValue("id"),r.Header.Get("X-AgentGuard-TOTP"))
	if errors.Is(err,store.ErrNotFound){writeError(w,404,"not_found","API key not found");return}
	if errors.Is(err,store.ErrMFARequired){writeError(w,403,"mfa_required","Enroll TOTP MFA on the calling API key before revoking keys");return}
	if errors.Is(err,store.ErrMFAInvalid){writeError(w,403,"mfa_invalid","A valid, unused TOTP code is required");return}
	if errors.Is(err,store.ErrMFALocked){writeError(w,429,"mfa_locked","MFA verification is temporarily locked");return}
	if err!=nil{writeError(w,409,"revoke_failed",err.Error());return}
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
	id:=r.Header.Get("X-Request-ID");if len(id)>64||id==""||strings.Trim(id,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")!=""{id=fmt.Sprintf("%d",time.Now().UnixNano())}
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

func validSchemaHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value { return false }
	_, err := hex.DecodeString(value)
	return err == nil
}
