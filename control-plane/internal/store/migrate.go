package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func (s *Store) Migrate(ctx context.Context) error {
	entries,err:=fs.Glob(migrationFiles,"migrations/*.sql");if err!=nil{return err};sort.Strings(entries)
	for _,name:=range entries{data,err:=migrationFiles.ReadFile(name);if err!=nil{return err};if _,err=s.db.ExecContext(ctx,string(data));err!=nil{return fmt.Errorf("apply %s: %w",name,err)}}
	return nil
}
func slugify(value string)string{
	value=strings.ToLower(strings.TrimSpace(value));var b strings.Builder;dash:=false
	for _,r:=range value{if r>='a'&&r<='z'||r>='0'&&r<='9'{b.WriteRune(r);dash=false}else if !dash&&b.Len()>0{b.WriteByte('-');dash=true}}
	return strings.Trim(b.String(),"-")
}
