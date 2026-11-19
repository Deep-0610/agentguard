package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type AuditVerification struct {
	Valid bool `json:"valid"`
	EventsChecked int64 `json:"events_checked"`
	FirstInvalidSequence *int64 `json:"first_invalid_sequence,omitempty"`
}

func (s *Store) VerifyAuditChain(ctx context.Context,tenant string)(AuditVerification,error){
	rows,err:=s.db.QueryContext(ctx,`SELECT sequence,actor,actor_role,event_type,resource_type,resource_id,request_id,payload,previous_hash,event_hash FROM audit_events WHERE tenant_id=$1 ORDER BY sequence ASC`,tenant)
	if err!=nil{return AuditVerification{},err};defer rows.Close()
	result:=AuditVerification{Valid:true}
	var expectedPrevious= strings.Repeat("0",64)
	var expectedSequence int64=1
	for rows.Next(){
		var sequence int64
		var actor,role,event,resource,id,request,previous,storedHash string
		var payload []byte
		if err=rows.Scan(&sequence,&actor,&role,&event,&resource,&id,&request,&payload,&previous,&storedHash);err!=nil{return AuditVerification{},err}
		result.EventsChecked++
		var decoded any
		if err=json.Unmarshal(payload,&decoded);err!=nil{return AuditVerification{},err}
		canonicalPayload,err:=json.Marshal(decoded);if err!=nil{return AuditVerification{},err}
		canonical:=strings.Join([]string{tenant,fmt.Sprint(sequence),actor,role,event,resource,id,request,string(canonicalPayload),previous},"\x00")
		sum:=sha256.Sum256([]byte(canonical));calculated:=hex.EncodeToString(sum[:])
		if sequence!=expectedSequence||previous!=expectedPrevious||calculated!=storedHash{
			result.Valid=false;result.FirstInvalidSequence=&sequence;return result,nil
		}
		expectedPrevious=storedHash;expectedSequence++
	}
	if err=rows.Err();err!=nil{return AuditVerification{},err}
	var headSequence int64
	var headHash string
	if err=s.db.QueryRowContext(ctx,`SELECT sequence,last_hash FROM audit_heads WHERE tenant_id=$1`,tenant).Scan(&headSequence,&headHash);err!=nil{return AuditVerification{},err}
	if headSequence!=result.EventsChecked||headHash!=expectedPrevious{
		result.Valid=false
		invalid:=result.EventsChecked+1
		result.FirstInvalidSequence=&invalid
	}
	return result,nil
}

func (s *Store) ListIdentityEvents(ctx context.Context,tenant,identityID string,limit int)([]map[string]any,error){
	rows,err:=s.db.QueryContext(ctx,`SELECT event_type,actor,before_state,after_state,created_at FROM identity_events WHERE tenant_id=$1 AND identity_id=$2 ORDER BY created_at DESC LIMIT $3`,tenant,identityID,limit)
	if err!=nil{return nil,err};defer rows.Close()
	out:=[]map[string]any{}
	for rows.Next(){
		var event,actor string;var before,after []byte;var createdAt sql.NullTime
		if err=rows.Scan(&event,&actor,&before,&after,&createdAt);err!=nil{return nil,err}
		out=append(out,map[string]any{"event_type":event,"actor":actor,"before_state":json.RawMessage(before),"after_state":json.RawMessage(after),"created_at":createdAt.Time})
	}
	return out,rows.Err()
}
