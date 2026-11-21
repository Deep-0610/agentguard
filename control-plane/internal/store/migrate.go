package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil { return err }
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(734921840)`); err != nil { return fmt.Errorf("lock migrations: %w", err) }
	defer func() { _, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(734921840)`) }()
	if _,err:=conn.ExecContext(ctx,`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		checksum TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`);err!=nil{return fmt.Errorf("create migration ledger: %w",err)}
	entries,err:=fs.Glob(migrationFiles,"migrations/*.sql");if err!=nil{return err}
	sort.Strings(entries)
	for _,name:=range entries{
		data,err:=migrationFiles.ReadFile(name);if err!=nil{return err}
		sum:=sha256.Sum256(data);checksum:=hex.EncodeToString(sum[:])
		version:=strings.TrimSuffix(filepath.Base(name),".sql")
		var existing string
		err=conn.QueryRowContext(ctx,`SELECT checksum FROM schema_migrations WHERE version=$1`,version).Scan(&existing)
		if err==nil{
			if existing!=checksum{return fmt.Errorf("migration %s checksum changed after application; add a new migration instead",version)}
			continue
		}
		if err!=sql.ErrNoRows{return err}
		tx,err:=conn.BeginTx(ctx,nil);if err!=nil{return err}
		if _,err=tx.ExecContext(ctx,string(data));err!=nil{_ = tx.Rollback();return fmt.Errorf("apply %s: %w",name,err)}
		if _,err=tx.ExecContext(ctx,`INSERT INTO schema_migrations(version,checksum) VALUES($1,$2)`,version,checksum);err!=nil{_ = tx.Rollback();return err}
		if err=tx.Commit();err!=nil{return fmt.Errorf("commit %s: %w",name,err)}
	}
	return nil
}
func slugify(value string)string{
	value=strings.ToLower(strings.TrimSpace(value));var b strings.Builder;dash:=false
	for _,r:=range value{
		if r>='a'&&r<='z'||r>='0'&&r<='9'{b.WriteRune(r);dash=false
		}else if !dash&&b.Len()>0{b.WriteByte('-');dash=true}
	}
	return strings.Trim(b.String(),"-")
}
