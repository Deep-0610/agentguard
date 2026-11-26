package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func appendAudit(ctx context.Context,tx *sql.Tx,tenant,actor,role,event,resource,id,request string,payload map[string]any)error{
	data,err:=json.Marshal(payload);if err!=nil{return err}
	var sequence int64;var previous string
	err=tx.QueryRowContext(ctx,`UPDATE audit_heads SET sequence=sequence+1 WHERE tenant_id=$1 RETURNING sequence,last_hash`,tenant).Scan(&sequence,&previous)
	if err!=nil{return err}
	canonical:=strings.Join([]string{tenant,fmt.Sprint(sequence),actor,role,event,resource,id,request,string(data),previous},"\x00")
	sum:=sha256.Sum256([]byte(canonical));hash:=hex.EncodeToString(sum[:])
	_,err=tx.ExecContext(ctx,`INSERT INTO audit_events(tenant_id,sequence,actor,actor_role,event_type,resource_type,resource_id,request_id,payload,previous_hash,event_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)`,tenant,sequence,actor,role,event,resource,id,request,string(data),previous,hash)
	if err!=nil{return err}
	_,err=tx.ExecContext(ctx,`UPDATE audit_heads SET last_hash=$2 WHERE tenant_id=$1`,tenant,hash)
	return err
}
func (s *Store) audit(ctx context.Context,p Principal,event,resource,id string,payload map[string]any)error{
	tx,err:=s.db.BeginTx(ctx,nil);if err!=nil{return err};defer tx.Rollback()
	if err=appendAudit(ctx,tx,p.TenantID,p.KeyID,p.Role,event,resource,id,p.RequestID,payload);err!=nil{return err}
	return tx.Commit()
}

func (s *Store) Ingest(ctx context.Context,p Principal,req ScanRequest,payloadHash string)(IngestResult,error){
	tx,err:=s.db.BeginTx(ctx,nil);if err!=nil{return IngestResult{},err};defer tx.Rollback()
	var scanID string
	err=tx.QueryRowContext(ctx,`INSERT INTO scans(tenant_id,scan_key,source,scanner_version,collected_at,payload_sha256,asset_count,finding_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,scan_key) DO NOTHING RETURNING id::text`,p.TenantID,req.ScanID,req.Source,req.ScannerVersion,req.CollectedAt,payloadHash,len(req.Assets),len(req.Findings)).Scan(&scanID)
	if err==sql.ErrNoRows{
		var existing string
		if e:=tx.QueryRowContext(ctx,`SELECT payload_sha256 FROM scans WHERE tenant_id=$1 AND scan_key=$2`,p.TenantID,req.ScanID).Scan(&existing);e!=nil{return IngestResult{},e}
		if existing!=payloadHash{return IngestResult{},ErrDuplicateScan}
		return IngestResult{ScanID:req.ScanID,Duplicate:true},nil
	}
	if err!=nil{return IngestResult{},err}
	result:=IngestResult{ScanID:req.ScanID}
	for _,a:=range req.Assets{
		external:=strings.TrimSpace(a.ExternalID);if external==""{external=a.Kind+":"+a.Name}
		if len(external)>512{return IngestResult{},fmt.Errorf("asset external_id exceeds 512 characters")}
		if a.Kind==""{a.Kind="unknown"};if a.OwnerStatus==""{a.OwnerStatus="UNKNOWN"};if a.Environment==""{a.Environment="unknown"};if a.Scopes==nil{a.Scopes=[]string{}}
		meta:=[]byte("{}")
		_,err=tx.ExecContext(ctx,`INSERT INTO identities(tenant_id,external_key,source,kind,name,owner_email,owner_status,environment,scopes,risk_score,last_scan_id,metadata) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11,$12::jsonb) ON CONFLICT(tenant_id,external_key) DO UPDATE SET source=EXCLUDED.source,kind=EXCLUDED.kind,name=EXCLUDED.name,owner_email=COALESCE(EXCLUDED.owner_email,identities.owner_email),owner_status=EXCLUDED.owner_status,environment=EXCLUDED.environment,scopes=EXCLUDED.scopes,risk_score=EXCLUDED.risk_score,last_seen_at=now(),last_scan_id=EXCLUDED.last_scan_id,metadata=EXCLUDED.metadata,updated_at=now()`,p.TenantID,a.Source+":"+external,a.Source,a.Kind,a.Name,a.OwnerEmail,a.OwnerStatus,a.Environment,a.Scopes,a.RiskScore,scanID,string(meta))
		if err!=nil{return IngestResult{},err}; if _,err=tx.ExecContext(ctx, `UPDATE identities SET verified=$3,secret_age_days=NULLIF($4,0),last_used_at=$5 WHERE tenant_id=$1 AND external_key=$2`,p.TenantID,a.Source+":"+external,a.Verified,a.SecretAgeDays,a.LastUsedAt);err!=nil{return IngestResult{},err}; result.AssetsUpserted++
	}
	for _,rel:=range req.Relationships{
		var fromID,toID string
		fromKey:=rel.FromSource+":"+rel.FromExternalID
		toKey:=rel.ToSource+":"+rel.ToExternalID
		if err=tx.QueryRowContext(ctx,`SELECT id::text FROM identities WHERE tenant_id=$1 AND external_key=$2`,p.TenantID,fromKey).Scan(&fromID);err!=nil{return IngestResult{},fmt.Errorf("relationship source identity %q not found in tenant inventory",fromKey)}
		if err=tx.QueryRowContext(ctx,`SELECT id::text FROM identities WHERE tenant_id=$1 AND external_key=$2`,p.TenantID,toKey).Scan(&toID);err!=nil{return IngestResult{},fmt.Errorf("relationship target identity %q not found in tenant inventory",toKey)}
		_,err=tx.ExecContext(ctx,`INSERT INTO identity_relationships(tenant_id,from_identity_id,to_identity_id,relationship_type,evidence) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,from_identity_id,to_identity_id,relationship_type) DO UPDATE SET evidence=EXCLUDED.evidence,last_seen_at=now(),updated_at=now()`,p.TenantID,fromID,toID,rel.Type,rel.Evidence)
		if err!=nil{return IngestResult{},err}
		result.RelationshipsUpserted++
	}
	for _,f:=range req.Findings{
		if f.Fingerprint==""{return IngestResult{},fmt.Errorf("finding fingerprint is required")}
		if f.Confidence==""{f.Confidence="medium"}
		var findingID string
		err=tx.QueryRowContext(ctx,`INSERT INTO findings(tenant_id,fingerprint,rule_id,severity,confidence,category,title,description,resource,location,evidence,remediation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(tenant_id,fingerprint) DO UPDATE SET severity=EXCLUDED.severity,confidence=EXCLUDED.confidence,category=EXCLUDED.category,title=EXCLUDED.title,description=EXCLUDED.description,resource=EXCLUDED.resource,location=EXCLUDED.location,evidence=EXCLUDED.evidence,remediation=EXCLUDED.remediation,last_seen_at=now(),occurrences=findings.occurrences+1,updated_at=now() RETURNING id::text`,p.TenantID,f.Fingerprint,f.RuleID,f.Severity,f.Confidence,f.Category,f.Title,f.Description,f.Resource,f.Location,f.Evidence,f.Remediation).Scan(&findingID)
		if err!=nil{return IngestResult{},err}
		if _,err=tx.ExecContext(ctx,`INSERT INTO scan_findings(tenant_id,scan_id,finding_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,p.TenantID,scanID,findingID);err!=nil{return IngestResult{},err}
		result.FindingsUpserted++
	}
	if err=appendAudit(ctx,tx,p.TenantID,p.KeyID,p.Role,"scan.ingested","scan",scanID,p.RequestID,map[string]any{"assets":result.AssetsUpserted,"findings":result.FindingsUpserted,"source":req.Source});err!=nil{return IngestResult{},err}
	if err=tx.Commit();err!=nil{return IngestResult{},err}
	return result,nil
}

func (s *Store) Summary(ctx context.Context,tenant string)(map[string]any,error){
	out:=map[string]any{}
	queries:=[]struct{key,query string}{
		{"identities","SELECT count(*) FROM identities WHERE tenant_id=$1"},
		{"open_findings","SELECT count(*) FROM findings WHERE tenant_id=$1 AND status='open' AND (suppression_expires_at IS NULL OR suppression_expires_at<=now())"},
		{"critical_findings","SELECT count(*) FROM findings WHERE tenant_id=$1 AND status='open' AND severity='critical' AND (suppression_expires_at IS NULL OR suppression_expires_at<=now())"},
		{"suppressed_findings","SELECT count(*) FROM findings WHERE tenant_id=$1 AND suppression_reason IS NOT NULL AND suppression_expires_at>now()"},
		{"orphaned_identities","SELECT count(*) FROM identities WHERE tenant_id=$1 AND owner_status IN ('UNKNOWN','SUSPENDED')"},
		{"scans_24h","SELECT count(*) FROM scans WHERE tenant_id=$1 AND collected_at>now()-interval '24 hours'"},
	}
	for _,item:=range queries{var n int64;if err:=s.db.QueryRowContext(ctx,item.query,tenant).Scan(&n);err!=nil{return nil,err};out[item.key]=n}
	return out,nil
}
func (s *Store) ListIdentities(ctx context.Context,tenant string,limit int)([]map[string]any,error){
	rows,err:=s.db.QueryContext(ctx,`SELECT id::text,external_key,source,kind,name,owner_email,owner_status,environment,to_json(scopes)::text,risk_score,first_seen_at,last_seen_at FROM identities WHERE tenant_id=$1 ORDER BY risk_score DESC,last_seen_at DESC LIMIT $2`,tenant,limit)
	if err!=nil{return nil,err};defer rows.Close();out:=[]map[string]any{}
	for rows.Next(){var id,external,source,kind,name,status,environment string;var owner sql.NullString;var scopesJSON string;var scopes []string;var score int;var first,last time.Time
		if err=rows.Scan(&id,&external,&source,&kind,&name,&owner,&status,&environment,&scopesJSON,&score,&first,&last);err!=nil{return nil,err}
		if err=json.Unmarshal([]byte(scopesJSON),&scopes);err!=nil{return nil,err}
		out=append(out,map[string]any{"id":id,"external_id":external,"source":source,"kind":kind,"name":name,"owner_email":owner.String,"owner_status":status,"environment":environment,"scopes":scopes,"risk_score":score,"first_seen_at":first,"last_seen_at":last})
	};return out,rows.Err()
}
func (s *Store) ListFindings(ctx context.Context,tenant,status string,limit int)([]map[string]any,error){
	query:=`SELECT id::text,fingerprint,rule_id,severity,confidence,category,title,description,resource,location,evidence,remediation,status,first_seen_at,last_seen_at,occurrences,suppression_reason,suppression_expires_at FROM findings WHERE tenant_id=$1`
	args:=[]any{tenant};if status!=""{query+=` AND status=$2`;args=append(args,status)}
	query+=fmt.Sprintf(" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,last_seen_at DESC LIMIT $%d",len(args)+1);args=append(args,limit)
	rows,err:=s.db.QueryContext(ctx,query,args...);if err!=nil{return nil,err};defer rows.Close();out:=[]map[string]any{}
	for rows.Next(){var id,fp,rule,severity,confidence,category,title,description,resource,location,evidence,remediation,state string;var first,last time.Time;var occurrences int64;var suppressionReason sql.NullString;var suppressionExpires sql.NullTime
		if err=rows.Scan(&id,&fp,&rule,&severity,&confidence,&category,&title,&description,&resource,&location,&evidence,&remediation,&state,&first,&last,&occurrences,&suppressionReason,&suppressionExpires);err!=nil{return nil,err}
		out=append(out,map[string]any{"id":id,"fingerprint":fp,"rule_id":rule,"severity":severity,"confidence":confidence,"category":category,"title":title,"description":description,"resource":resource,"location":location,"evidence":evidence,"remediation":remediation,"status":state,"first_seen_at":first,"last_seen_at":last,"occurrences":occurrences,"suppression_reason":suppressionReason.String,"suppression_expires_at":nullableTime(suppressionExpires),"is_suppressed":suppressionExpires.Valid&&suppressionExpires.Time.After(time.Now())})
	};return out,rows.Err()
}
func (s *Store) ListAudit(ctx context.Context,tenant string,limit int)([]map[string]any,error){
	rows,err:=s.db.QueryContext(ctx,`SELECT sequence,actor,actor_role,event_type,resource_type,resource_id,request_id,payload,previous_hash,event_hash,created_at FROM audit_events WHERE tenant_id=$1 ORDER BY sequence DESC LIMIT $2`,tenant,limit)
	if err!=nil{return nil,err};defer rows.Close();out:=[]map[string]any{}
	for rows.Next(){var sequence int64;var actor,role,event,typ,id,request,previous,hash string;var payload []byte;var at time.Time
		if err=rows.Scan(&sequence,&actor,&role,&event,&typ,&id,&request,&payload,&previous,&hash,&at);err!=nil{return nil,err}
		out=append(out,map[string]any{"sequence":sequence,"actor":actor,"actor_role":role,"event":event,"resource_type":typ,"resource_id":id,"request_id":request,"payload":json.RawMessage(payload),"previous_hash":previous,"event_hash":hash,"created_at":at})
	};return out,rows.Err()
}
func (s *Store) SetFindingStatus(ctx context.Context,p Principal,id,status,reason string)error{
	allowed:=map[string]bool{"acknowledged":true,"accepted-risk":true,"remediated":true,"false-positive":true,"open":true}
	if !allowed[status]{return fmt.Errorf("invalid finding status")}
	tx,err:=s.db.BeginTx(ctx,nil);if err!=nil{return err};defer tx.Rollback()
	var old string
	err=tx.QueryRowContext(ctx,`SELECT status FROM findings WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,p.TenantID,id).Scan(&old)
	if err==sql.ErrNoRows{return ErrNotFound};if err!=nil{return err}
	if _,err=tx.ExecContext(ctx,`UPDATE findings SET status=$3,updated_at=now() WHERE tenant_id=$1 AND id=$2`,p.TenantID,id,status);err!=nil{return err}
	if _,err=tx.ExecContext(ctx,`INSERT INTO finding_events(tenant_id,finding_id,actor,previous_status,new_status,reason) VALUES($1,$2,$3,$4,$5,$6)`,p.TenantID,id,p.KeyID,old,status,reason);err!=nil{return err}
	if err=appendAudit(ctx,tx,p.TenantID,p.KeyID,p.Role,"finding.status_changed","finding",id,p.RequestID,map[string]any{"from":old,"to":status,"reason":reason});err!=nil{return err}
	return tx.Commit()
}


func nullableTime(v sql.NullTime) any {
	if !v.Valid { return nil }
	return v.Time
}

func (s *Store) SetFindingSuppression(ctx context.Context,p Principal,id,reason string,expiresAt time.Time) error {
	reason=strings.TrimSpace(reason)
	if reason==""||len(reason)>1000 { return fmt.Errorf("suppression reason is required and must be at most 1000 characters") }
	now:=time.Now().UTC()
	if !expiresAt.After(now)||expiresAt.After(now.Add(90*24*time.Hour)) { return fmt.Errorf("suppression expiry must be within the next 90 days") }
	tx,err:=s.db.BeginTx(ctx,nil);if err!=nil{return err};defer tx.Rollback()
	var title string
	err=tx.QueryRowContext(ctx,`SELECT title FROM findings WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,p.TenantID,id).Scan(&title)
	if err==sql.ErrNoRows{return ErrNotFound};if err!=nil{return err}
	if _,err=tx.ExecContext(ctx,`UPDATE findings SET suppression_reason=$3,suppression_expires_at=$4,updated_at=now() WHERE tenant_id=$1 AND id=$2`,p.TenantID,id,reason,expiresAt);err!=nil{return err}
	if err=appendAudit(ctx,tx,p.TenantID,p.KeyID,p.Role,"finding.suppressed","finding",id,p.RequestID,map[string]any{"reason":reason,"expires_at":expiresAt.UTC()});err!=nil{return err}
	return tx.Commit()
}

func (s *Store) ClearFindingSuppression(ctx context.Context,p Principal,id,reason string) error {
	reason=strings.TrimSpace(reason)
	if reason==""||len(reason)>1000{return fmt.Errorf("unsuppression reason is required and must be at most 1000 characters")}
	tx,err:=s.db.BeginTx(ctx,nil);if err!=nil{return err};defer tx.Rollback()
	var previous sql.NullString
	err=tx.QueryRowContext(ctx,`SELECT suppression_reason FROM findings WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,p.TenantID,id).Scan(&previous)
	if err==sql.ErrNoRows{return ErrNotFound};if err!=nil{return err}
	if !previous.Valid{return fmt.Errorf("finding is not currently suppressed")}
	if _,err=tx.ExecContext(ctx,`UPDATE findings SET suppression_reason=NULL,suppression_expires_at=NULL,updated_at=now() WHERE tenant_id=$1 AND id=$2`,p.TenantID,id);err!=nil{return err}
	if err=appendAudit(ctx,tx,p.TenantID,p.KeyID,p.Role,"finding.unsuppressed","finding",id,p.RequestID,map[string]any{"previous_reason":previous.String,"reason":reason});err!=nil{return err}
	return tx.Commit()
}

func (s *Store) ListFindingEvents(ctx context.Context,tenant,id string,limit int)([]map[string]any,error){
	rows,err:=s.db.QueryContext(ctx,`SELECT e.actor,e.previous_status,e.new_status,e.reason,e.created_at FROM finding_events e JOIN findings f ON f.tenant_id=e.tenant_id AND f.id=e.finding_id WHERE e.tenant_id=$1 AND e.finding_id=$2 ORDER BY e.created_at DESC LIMIT $3`,tenant,id,limit)
	if err!=nil{return nil,err};defer rows.Close()
	out:=[]map[string]any{}
	for rows.Next(){var actor,previous,next,reason string;var at time.Time;if err=rows.Scan(&actor,&previous,&next,&reason,&at);err!=nil{return nil,err};out=append(out,map[string]any{"actor":actor,"previous_status":previous,"new_status":next,"reason":reason,"created_at":at})}
	return out,rows.Err()
}
