package store

import (
	"context"
	"time"
)

func (s *Store) ListRelationships(ctx context.Context,tenant string,limit int)([]map[string]any,error){
	rows,err:=s.db.QueryContext(ctx,`SELECT r.id::text,r.relationship_type,r.evidence,r.first_seen_at,r.last_seen_at,
		f.id::text,f.kind,f.name,t.id::text,t.kind,t.name
		FROM identity_relationships r
		JOIN identities f ON f.tenant_id=r.tenant_id AND f.id=r.from_identity_id
		JOIN identities t ON t.tenant_id=r.tenant_id AND t.id=r.to_identity_id
		WHERE r.tenant_id=$1
		ORDER BY r.last_seen_at DESC
		LIMIT $2`,tenant,limit)
	if err!=nil{return nil,err};defer rows.Close()
	out:=[]map[string]any{}
	for rows.Next(){
		var id,kind,evidence,fromID,fromKind,fromName,toID,toKind,toName string
		var first,last time.Time
		if err=rows.Scan(&id,&kind,&evidence,&first,&last,&fromID,&fromKind,&fromName,&toID,&toKind,&toName);err!=nil{return nil,err}
		out=append(out,map[string]any{"id":id,"type":kind,"evidence":evidence,"first_seen_at":first,"last_seen_at":last,"from":map[string]any{"id":fromID,"kind":fromKind,"name":fromName},"to":map[string]any{"id":toID,"kind":toKind,"name":toName}})
	}
	return out,rows.Err()
}
