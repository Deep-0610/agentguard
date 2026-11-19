package store

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var schemaHashPattern = regexp.MustCompile("^[a-f0-9]{64}$")

type ToolBaseline struct {
	Name string `json:"name"`
	ApprovedSchemaHash string `json:"approved_schema_hash"`
	Risk string `json:"risk"`
	ApprovedBy string `json:"approved_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Store) SetToolBaseline(ctx context.Context, p Principal, name, schemaHash, risk string) (ToolBaseline, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 256 { return ToolBaseline{}, fmt.Errorf("tool name is required and must be at most 256 characters") }
	if !schemaHashPattern.MatchString(schemaHash) { return ToolBaseline{}, fmt.Errorf("approved schema hash must be a lowercase SHA-256 hex digest") }
	if risk != "low" && risk != "medium" && risk != "high" && risk != "critical" { return ToolBaseline{}, fmt.Errorf("risk must be low, medium, high, or critical") }
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return ToolBaseline{}, err }
	defer tx.Rollback()
	var baseline ToolBaseline
	err = tx.QueryRowContext(ctx, `INSERT INTO tool_baselines(tenant_id,tool_name,approved_schema_hash,risk,approved_by)
		VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(tenant_id,tool_name) DO UPDATE SET approved_schema_hash=EXCLUDED.approved_schema_hash,risk=EXCLUDED.risk,approved_by=EXCLUDED.approved_by,updated_at=now()
		RETURNING tool_name,approved_schema_hash,risk,approved_by,updated_at`, p.TenantID, name, schemaHash, risk, p.KeyID).
		Scan(&baseline.Name, &baseline.ApprovedSchemaHash, &baseline.Risk, &baseline.ApprovedBy, &baseline.UpdatedAt)
	if err != nil { return ToolBaseline{}, err }
	if err = appendAudit(ctx, tx, p.TenantID, p.KeyID, p.Role, "tool_baseline.updated", "tool_baseline", name, "", map[string]any{"risk": risk, "approved_schema_hash": schemaHash}); err != nil { return ToolBaseline{}, err }
	if err = tx.Commit(); err != nil { return ToolBaseline{}, err }
	return baseline, nil
}

func (s *Store) GetToolBaseline(ctx context.Context, tenant, name string) (ToolBaseline, error) {
	var baseline ToolBaseline
	err := s.db.QueryRowContext(ctx, `SELECT tool_name,approved_schema_hash,risk,approved_by,updated_at FROM tool_baselines WHERE tenant_id=$1 AND tool_name=$2`, tenant, name).
		Scan(&baseline.Name, &baseline.ApprovedSchemaHash, &baseline.Risk, &baseline.ApprovedBy, &baseline.UpdatedAt)
	if err == sql.ErrNoRows { return ToolBaseline{}, ErrNotFound }
	return baseline, err
}

func (s *Store) ListToolBaselines(ctx context.Context, tenant string, limit int) ([]ToolBaseline, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tool_name,approved_schema_hash,risk,approved_by,updated_at FROM tool_baselines WHERE tenant_id=$1 ORDER BY tool_name LIMIT $2`, tenant, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	out := []ToolBaseline{}
	for rows.Next() {
		var baseline ToolBaseline
		if err = rows.Scan(&baseline.Name, &baseline.ApprovedSchemaHash, &baseline.Risk, &baseline.ApprovedBy, &baseline.UpdatedAt); err != nil { return nil, err }
		out = append(out, baseline)
	}
	return out, rows.Err()
}
