package store

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var ErrNotFound = errors.New("not found")
var ErrDuplicateScan = errors.New("scan id already exists with different content")

type Store struct { db *sql.DB; pepper []byte }
type Principal struct { TenantID string; KeyID string; Role string; Name string; RequestID string }
type APIKey struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
	Prefix string `json:"prefix"`
	CreatedAt time.Time `json:"created_at"`
	LastUsedAt *time.Time `json:"-"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}
type AssetInput struct {
	ExternalID string `json:"external_id"`
	Source string `json:"source"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	OwnerEmail string `json:"-"`
	OwnerStatus string `json:"-"`
	Environment string `json:"environment,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	RiskScore int `json:"-"`
	Verified bool `json:"-"`
	SecretAgeDays int `json:"-"`
	LastUsedAt *time.Time `json:"-"`
}
type FindingInput struct {
	Fingerprint string `json:"fingerprint"`
	RuleID string `json:"rule_id"`
	Severity string `json:"severity"`
	Confidence string `json:"confidence,omitempty"`
	Category string `json:"category"`
	Title string `json:"title"`
	Description string `json:"description,omitempty"`
	Resource string `json:"resource,omitempty"`
	Location string `json:"location,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}
type RelationshipInput struct {
	FromSource string `json:"from_source"`
	FromExternalID string `json:"from_external_id"`
	ToSource string `json:"to_source"`
	ToExternalID string `json:"to_external_id"`
	Type string `json:"type"`
	Evidence string `json:"evidence,omitempty"`
}
type ScanRequest struct {
	ScanID string `json:"scan_id"`
	Source string `json:"source"`
	ScannerVersion string `json:"scanner_version,omitempty"`
	CollectedAt time.Time `json:"collected_at"`
	Assets []AssetInput `json:"assets,omitempty"`
	Findings []FindingInput `json:"findings,omitempty"`
	Relationships []RelationshipInput `json:"relationships,omitempty"`
}
type IngestResult struct {
	ScanID string `json:"scan_id"`
	AssetsUpserted int `json:"assets_upserted"`
	FindingsUpserted int `json:"findings_upserted"`
	RelationshipsUpserted int `json:"relationships_upserted"`
	Duplicate bool `json:"duplicate"`
}

func Open(ctx context.Context, dsn, pepper string) (*Store,error) {
	db,err:=sql.Open("pgx",dsn);if err!=nil{return nil,err}
	db.SetMaxOpenConns(20);db.SetMaxIdleConns(5);db.SetConnMaxLifetime(30*time.Minute)
	if err=db.PingContext(ctx);err!=nil{_ = db.Close();return nil,fmt.Errorf("connect database: %w",err)}
	return &Store{db:db,pepper:[]byte(pepper)},nil
}
func (s *Store) Close()error{return s.db.Close()}
func randomHex(n int)(string,error){b:=make([]byte,n);if _,err:=rand.Read(b);err!=nil{return "",err};return hex.EncodeToString(b),nil}
func keyDigest(secret string,pepper []byte)[]byte{mac:=hmac.New(sha256.New,pepper);_,_=mac.Write([]byte(secret));return mac.Sum(nil)}
func makeKey()(string,string,string,error){
	id,err:=randomHex(8);if err!=nil{return "","","",err}
	b:=make([]byte,32);if _,err=rand.Read(b);err!=nil{return "","","",err}
	secret:=base64.RawURLEncoding.EncodeToString(b)
	return id,secret,"ag_live_"+id+"."+secret,nil
}
func (s *Store) Bootstrap(ctx context.Context,name string)(string,string,error){
	name=strings.TrimSpace(name);slug:=slugify(name)
	if len(name)<2||len(name)>160||len(slug)<2||len(slug)>63{return "","",fmt.Errorf("organization name must produce a 2-63 character URL slug")}
	keyID,secret,token,err:=makeKey();if err!=nil{return "","",err}
	tx,err:=s.db.BeginTx(ctx,nil);if err!=nil{return "","",err};defer tx.Rollback()
	var tenantID string
	if err=tx.QueryRowContext(ctx,`INSERT INTO tenants(name,slug) VALUES($1,$2) RETURNING id::text`,name,slug).Scan(&tenantID);err!=nil{return "","",err}
	if _,err=tx.ExecContext(ctx,`INSERT INTO audit_heads(tenant_id) VALUES($1)`,tenantID);err!=nil{return "","",err}
	if _,err=tx.ExecContext(ctx,`INSERT INTO api_keys(tenant_id,key_id,secret_hash,name,role) VALUES($1,$2,$3,$4,'owner')`,tenantID,keyID,keyDigest(secret,s.pepper),"Initial owner key");err!=nil{return "","",err}
	if err=appendAudit(ctx,tx,tenantID,"bootstrap","owner","organization.created","tenant",tenantID,"",map[string]any{"name":name,"slug":slug});err!=nil{return "","",err}
	if err=tx.Commit();err!=nil{return "","",err}
	return tenantID,token,nil
}
func (s *Store) Authenticate(ctx context.Context,token string)(Principal,error){
	if !strings.HasPrefix(token,"ag_live_"){return Principal{},ErrNotFound}
	parts:=strings.SplitN(strings.TrimPrefix(token,"ag_live_"),".",2)
	if len(parts)!=2||len(parts[0])!=16||len(parts[1])<40{return Principal{},ErrNotFound}
	var p Principal;var hash []byte;var revoked,expires sql.NullTime;var tenantStatus string
	err:=s.db.QueryRowContext(ctx,`SELECT k.tenant_id::text,k.key_id,k.role,k.name,k.secret_hash,k.revoked_at,k.expires_at,t.status FROM api_keys k JOIN tenants t ON t.id=k.tenant_id WHERE k.key_id=$1`,parts[0]).Scan(&p.TenantID,&p.KeyID,&p.Role,&p.Name,&hash,&revoked,&expires,&tenantStatus)
	if err!=nil{return Principal{},ErrNotFound}
	if tenantStatus!="active"||revoked.Valid||(expires.Valid&&time.Now().After(expires.Time))||!hmac.Equal(hash,keyDigest(parts[1],s.pepper)){return Principal{},ErrNotFound}
	_,_=s.db.ExecContext(ctx,`UPDATE api_keys SET last_used_at=now() WHERE key_id=$1`,p.KeyID)
	return p,nil
}
func (s *Store) CreateAPIKey(ctx context.Context,p Principal,name,role string,expires *time.Time)(APIKey,string,error){
	if role!="owner"&&role!="admin"&&role!="analyst"&&role!="viewer"&&role!="ingest"{return APIKey{},"",fmt.Errorf("unsupported API key role")}
	if role=="owner"&&p.Role!="owner"{return APIKey{},"",fmt.Errorf("only an owner can create another owner key")}
	if strings.TrimSpace(name)==""||len(name)>120{return APIKey{},"",fmt.Errorf("key name is required and must be at most 120 characters")}
	keyID,secret,token,err:=makeKey();if err!=nil{return APIKey{},"",err}
	tx,err:=s.db.BeginTx(ctx,nil);if err!=nil{return APIKey{},"",err};defer tx.Rollback()
	var tenantLock string
	if err=tx.QueryRowContext(ctx,`SELECT id::text FROM tenants WHERE id=$1 FOR UPDATE`,p.TenantID).Scan(&tenantLock);err!=nil{return APIKey{},"",err}
	var key APIKey
	err=tx.QueryRowContext(ctx,`INSERT INTO api_keys(tenant_id,key_id,secret_hash,name,role,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id::text,name,role,created_at,expires_at`,p.TenantID,keyID,keyDigest(secret,s.pepper),strings.TrimSpace(name),role,expires,p.KeyID).Scan(&key.ID,&key.Name,&key.Role,&key.CreatedAt,&key.ExpiresAt)
	if err!=nil{return APIKey{},"",err}
	key.Prefix="ag_live_"+keyID[:8]
	if err=appendAudit(ctx,tx,p.TenantID,p.KeyID,p.Role,"api_key.created","api_key",key.ID,"",map[string]any{"name":key.Name,"role":key.Role});err!=nil{return APIKey{},"",err}
	if err=tx.Commit();err!=nil{return APIKey{},"",err}
	return key,token,nil
}
func (s *Store) ListAPIKeys(ctx context.Context,tenant string)([]APIKey,error){
	rows,err:=s.db.QueryContext(ctx,`SELECT id::text,name,role,'ag_live_'||left(key_id,8),created_at,last_used_at,expires_at,revoked_at FROM api_keys WHERE tenant_id=$1 ORDER BY created_at DESC`,tenant);if err!=nil{return nil,err};defer rows.Close()
	out:=[]APIKey{}
	for rows.Next(){var k APIKey;var last,expires,revoked sql.NullTime;if err=rows.Scan(&k.ID,&k.Name,&k.Role,&k.Prefix,&k.CreatedAt,&last,&expires,&revoked);err!=nil{return nil,err};if last.Valid{k.LastUsedAt=&last.Time};if expires.Valid{k.ExpiresAt=&expires.Time};if revoked.Valid{k.RevokedAt=&revoked.Time};out=append(out,k)}
	return out,rows.Err()
}
func (s *Store) RevokeAPIKey(ctx context.Context,p Principal,id string)error{
	tx,err:=s.db.BeginTx(ctx,nil);if err!=nil{return err};defer tx.Rollback()
	var tenantLock string
	if err=tx.QueryRowContext(ctx,`SELECT id::text FROM tenants WHERE id=$1 FOR UPDATE`,p.TenantID).Scan(&tenantLock);err!=nil{return err}
	var targetRole string
	err=tx.QueryRowContext(ctx,`SELECT role FROM api_keys WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL FOR UPDATE`,p.TenantID,id).Scan(&targetRole)
	if err==sql.ErrNoRows{return ErrNotFound};if err!=nil{return err}
	if targetRole=="owner"{
		var owners int
		if err=tx.QueryRowContext(ctx,`SELECT count(*) FROM api_keys WHERE tenant_id=$1 AND role='owner' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())`,p.TenantID).Scan(&owners);err!=nil{return err}
		if owners<=1{return fmt.Errorf("cannot revoke the last active owner key")}
	}
	_,err=tx.ExecContext(ctx,`UPDATE api_keys SET revoked_at=now() WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`,p.TenantID,id);if err!=nil{return err}
	if err=appendAudit(ctx,tx,p.TenantID,p.KeyID,p.Role,"api_key.revoked","api_key",id,"",map[string]any{"target_role":targetRole});err!=nil{return err}
	return tx.Commit()
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}
