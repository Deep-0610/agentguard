package store

import (
	"context"
	"fmt"
	"os"
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
	if err=s.Migrate(ctx);err!=nil{t.Fatal(err)}
	suffix:=fmt.Sprintf("%d",time.Now().UnixNano())
	tenantA,keyA,err:=s.Bootstrap(ctx,"Tenant A "+suffix);if err!=nil{t.Fatal(err)}
	tenantB,keyB,err:=s.Bootstrap(ctx,"Tenant B "+suffix);if err!=nil{t.Fatal(err)}
	principalA,err:=s.Authenticate(ctx,keyA);if err!=nil{t.Fatal(err)}
	principalB,err:=s.Authenticate(ctx,keyB);if err!=nil{t.Fatal(err)}
	if principalA.TenantID!=tenantA||principalB.TenantID!=tenantB{t.Fatal("API key resolved to wrong tenant")}
	req:=ScanRequest{ScanID:"integration-"+suffix,Source:"test",CollectedAt:time.Now().UTC(),Assets:[]AssetInput{{ExternalID:"mcp:test",Source:"mcp",Kind:"mcp_server",Name:"test-server",OwnerStatus:"UNKNOWN"}},Findings:[]FindingInput{{Fingerprint:"fp-"+suffix,RuleID:"test.rule",Severity:"high",Confidence:"high",Category:"test",Title:"Test finding"}}}
	ingested,err:=s.Ingest(ctx,principalA,req,"payload-"+suffix);if err!=nil{t.Fatal(err)}
	if ingested.AssetsUpserted!=1||ingested.FindingsUpserted!=1{t.Fatalf("unexpected ingest result: %+v",ingested)}
	updated:=req
	updated.ScanID="integration-drift-"+suffix
	updated.Assets=[]AssetInput{{ExternalID:"mcp:test",Source:"mcp",Kind:"mcp_server",Name:"test-server",OwnerStatus:"ACTIVE",Scopes:[]string{"read"}}}
	if _,err=s.Ingest(ctx,principalA,updated,"payload-drift-"+suffix);err!=nil{t.Fatal(err)}
	identityEvents,err:=s.ListIdentityEvents(ctx,tenantA,func()string{items,e:=s.ListIdentities(ctx,tenantA,10);if e!=nil||len(items)==0{return ""};return items[0]["id"].(string)}(),10)
	if err!=nil{t.Fatal(err)}
	if len(identityEvents)==0{t.Fatal("expected identity drift history after owner state changed")}
	audit,err:=s.VerifyAuditChain(ctx,tenantA);if err!=nil{t.Fatal(err)}
	if !audit.Valid||audit.EventsChecked<3{t.Fatalf("audit chain failed verification: %+v",audit)}
	summaryA,err:=s.Summary(ctx,tenantA);if err!=nil{t.Fatal(err)}
	summaryB,err:=s.Summary(ctx,tenantB);if err!=nil{t.Fatal(err)}
	if summaryA["identities"].(int64)!=1||summaryA["open_findings"].(int64)!=1{t.Fatalf("tenant A did not receive ingested records: %#v",summaryA)}
	if summaryB["identities"].(int64)!=0||summaryB["open_findings"].(int64)!=0{t.Fatalf("tenant B can see tenant A records: %#v",summaryB)}
	duplicate,err:=s.Ingest(ctx,principalA,req,"payload-"+suffix);if err!=nil{t.Fatal(err)}
	if !duplicate.Duplicate{t.Fatal("expected identical scan ingestion to be idempotent")}
	_,err=s.Ingest(ctx,principalA,req,"different-payload")
	if err!=ErrDuplicateScan{t.Fatalf("expected idempotency conflict, got %v",err)}
}
