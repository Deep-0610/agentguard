package store

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func TestTenantIsolationAndIngestion(t *testing.T) {
	dsn:=os.Getenv("AG_DATABASE_URL")
	if dsn=="" { t.Skip("AG_DATABASE_URL is not set") }
	pepper:=os.Getenv("AG_API_KEY_PEPPER")
	if len(pepper)<32 { t.Fatal("test API key pepper must be at least 32 characters") }
	ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
	s,err:=Open(ctx,dsn,pepper);if err!=nil{t.Fatal(err)};defer s.Close()
	var migrationWG sync.WaitGroup
	migrationErrors:=make(chan error,2)
	for i:=0;i<2;i++{migrationWG.Add(1);go func(){defer migrationWG.Done();migrationErrors<-s.Migrate(ctx)}()}
	migrationWG.Wait();close(migrationErrors)
	for migrationErr:=range migrationErrors{if migrationErr!=nil{t.Fatalf("concurrent migration failed: %v",migrationErr)}}
	suffix:=fmt.Sprintf("%d",time.Now().UnixNano())
	tenantA,keyA,err:=s.Bootstrap(ctx,"Tenant A "+suffix);if err!=nil{t.Fatal(err)}
	tenantB,keyB,err:=s.Bootstrap(ctx,"Tenant B "+suffix);if err!=nil{t.Fatal(err)}
	principalA,err:=s.Authenticate(ctx,keyA);if err!=nil{t.Fatal(err)}
	principalB,err:=s.Authenticate(ctx,keyB);if err!=nil{t.Fatal(err)}
	if principalA.TenantID!=tenantA||principalB.TenantID!=tenantB{t.Fatal("API key resolved to wrong tenant")}
	req:=ScanRequest{ScanID:"integration-"+suffix,Source:"test",CollectedAt:time.Now().UTC(),Assets:[]AssetInput{{ExternalID:"mcp:test",Source:"mcp",Kind:"mcp_server",Name:"test-server",OwnerStatus:"UNKNOWN"},{ExternalID:"app:helper",Source:"github",Kind:"oauth_app",Name:"helper-app",OwnerStatus:"ACTIVE",Verified:true}},Relationships:[]RelationshipInput{{FromSource:"mcp",FromExternalID:"mcp:test",ToSource:"github",ToExternalID:"app:helper",Type:"uses"}},Findings:[]FindingInput{{Fingerprint:"fp-"+suffix,RuleID:"test.rule",Severity:"high",Confidence:"high",Category:"test",Title:"Test finding"}}}
	ingested,err:=s.Ingest(ctx,principalA,req,"payload-"+suffix);if err!=nil{t.Fatal(err)}
	if ingested.AssetsUpserted!=2||ingested.FindingsUpserted!=1||ingested.RelationshipsUpserted!=1{t.Fatalf("unexpected ingest result: %+v",ingested)}
	updated:=req
	updated.ScanID="integration-drift-"+suffix
	updated.Assets=[]AssetInput{{ExternalID:"mcp:test",Source:"mcp",Kind:"mcp_server",Name:"test-server",OwnerStatus:"ACTIVE",Scopes:[]string{"read"}}}
	if _,err=s.Ingest(ctx,principalA,updated,"payload-drift-"+suffix);err!=nil{t.Fatal(err)}
	identityRows,err:=s.ListIdentities(ctx,tenantA,10);if err!=nil{t.Fatal(err)};if len(identityRows)==0{t.Fatal("expected identities after ingestion")};identityID,ok:=identityRows[0]["id"].(string);if !ok||identityID==""{t.Fatalf("invalid identity row: %#v",identityRows[0])};identityEvents,err:=s.ListIdentityEvents(ctx,tenantA,identityID,10)
	if err!=nil{t.Fatal(err)}
	if len(identityEvents)==0{t.Fatal("expected identity drift history after owner state changed")}
	audit,err:=s.VerifyAuditChain(ctx,tenantA);if err!=nil{t.Fatal(err)}
	if !audit.Valid||audit.EventsChecked<3{t.Fatalf("audit chain failed verification: %+v",audit)}
	relationships,err:=s.ListRelationships(ctx,tenantA,10);if err!=nil{t.Fatal(err)}
	if len(relationships)!=1{t.Fatalf("expected one tenant identity relationship, got %d",len(relationships))}
	summaryA,err:=s.Summary(ctx,tenantA);if err!=nil{t.Fatal(err)}
	summaryB,err:=s.Summary(ctx,tenantB);if err!=nil{t.Fatal(err)}
	if summaryA["identities"].(int64)!=2||summaryA["open_findings"].(int64)!=1{t.Fatalf("tenant A did not receive ingested records: %#v",summaryA)}
	if summaryB["identities"].(int64)!=0||summaryB["open_findings"].(int64)!=0{t.Fatalf("tenant B can see tenant A records: %#v",summaryB)}
	duplicate,err:=s.Ingest(ctx,principalA,req,"payload-"+suffix);if err!=nil{t.Fatal(err)}
	if !duplicate.Duplicate{t.Fatal("expected identical scan ingestion to be idempotent")}
	_,err=s.Ingest(ctx,principalA,req,"different-payload")
	if err!=ErrDuplicateScan{t.Fatalf("expected idempotency conflict, got %v",err)}
	backupKey,backupSecret,err:=s.CreateAPIKey(ctx,principalA,"Backup owner","owner",nil);if err!=nil{t.Fatal(err)}
	var originalKeyID string
	if err=s.db.QueryRowContext(ctx,`SELECT id::text FROM api_keys WHERE tenant_id=$1 AND key_id=$2`,tenantA,principalA.KeyID).Scan(&originalKeyID);err!=nil{t.Fatal(err)}
	if err=s.RevokeAPIKey(ctx,principalA,originalKeyID);err!=nil{t.Fatal(err)}
	backupPrincipal,err:=s.Authenticate(ctx,backupSecret);if err!=nil{t.Fatal(err)}
	if err=s.RevokeAPIKey(ctx,backupPrincipal,backupKey.ID);err==nil{t.Fatal("expected last active owner key revocation to be blocked")}
	if _,err=s.Authenticate(ctx,keyA);err==nil{t.Fatal("revoked API key must no longer authenticate")}
	hash:="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _,err=s.SetToolBaseline(ctx,backupPrincipal,"internal.search",hash,"low");err!=nil{t.Fatal(err)}
	baseline,err:=s.GetToolBaseline(ctx,tenantA,"internal.search");if err!=nil{t.Fatal(err)}
	if baseline.ApprovedSchemaHash!=hash||baseline.Risk!="low"{t.Fatalf("unexpected tool baseline: %+v",baseline)}
	if _,err=s.GetToolBaseline(ctx,tenantB,"internal.search");err!=ErrNotFound{t.Fatalf("tenant B must not see tenant A baseline: %v",err)}
	secondOwner,secondSecret,err:=s.CreateAPIKey(ctx,backupPrincipal,"Concurrent owner","owner",nil);if err!=nil{t.Fatal(err)}
	secondPrincipal,err:=s.Authenticate(ctx,secondSecret);if err!=nil{t.Fatal(err)}
	_ = secondPrincipal
	var ownerWG sync.WaitGroup
	revokeResults:=make(chan error,2)
	for _,id:=range []string{backupKey.ID,secondOwner.ID}{ownerWG.Add(1);go func(target string){defer ownerWG.Done();revokeResults<-s.RevokeAPIKey(ctx,backupPrincipal,target)}(id)}
	ownerWG.Wait();close(revokeResults)
	successes:=0
	for revokeErr:=range revokeResults{if revokeErr==nil{successes++}}
	if successes!=1{t.Fatalf("expected exactly one concurrent owner-key revocation to succeed, got %d",successes)}
	var activeOwners int
	if err=s.db.QueryRowContext(ctx,`SELECT count(*) FROM api_keys WHERE tenant_id=$1 AND role='owner' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())`,tenantA).Scan(&activeOwners);err!=nil{t.Fatal(err)}
	if activeOwners!=1{t.Fatalf("expected exactly one active owner key after concurrent revocation, got %d",activeOwners)}
	audit,err=s.VerifyAuditChain(ctx,tenantA);if err!=nil||!audit.Valid{t.Fatalf("audit chain invalid after tool baseline update: %+v %v",audit,err)}
}
