package config

import "testing"

func TestLoadRejectsInvalidTimeout(t *testing.T) {
	t.Setenv("AG_DATABASE_URL","postgres://localhost/agentguard")
	t.Setenv("AG_API_KEY_PEPPER","0123456789abcdef0123456789abcdef")
	t.Setenv("AG_READ_TIMEOUT","not-a-duration")
	if _,err:=Load();err==nil { t.Fatal("expected invalid timeout to fail") }
}
func TestLoadRejectsNonPositiveTimeout(t *testing.T) {
	t.Setenv("AG_DATABASE_URL","postgres://localhost/agentguard")
	t.Setenv("AG_API_KEY_PEPPER","0123456789abcdef0123456789abcdef")
	t.Setenv("AG_READ_TIMEOUT","0s")
	if _,err:=Load();err==nil { t.Fatal("expected non-positive timeout to fail") }
}
func TestLoadRequiresLongPepper(t *testing.T) {
	t.Setenv("AG_DATABASE_URL","postgres://localhost/agentguard")
	t.Setenv("AG_API_KEY_PEPPER","short")
	if _,err:=Load();err==nil { t.Fatal("expected short pepper to fail") }
}

func TestProductionRequiresVerifiedDatabaseTLS(t *testing.T) {
	t.Setenv("AG_ENV", "production")
	t.Setenv("AG_DATABASE_URL", "postgres://agentguard:secret@db.example/agentguard?sslmode=require")
	t.Setenv("AG_API_KEY_PEPPER", "0123456789abcdef0123456789abcdef")
	t.Setenv("AG_OPA_URL", "https://opa.example")
	if _, err := Load(); err == nil { t.Fatal("expected production to require sslmode=verify-full") }
}
func TestProductionRequiresHTTPSOPA(t *testing.T) {
	t.Setenv("AG_ENV", "production")
	t.Setenv("AG_DATABASE_URL", "postgres://agentguard:secret@db.example/agentguard?sslmode=verify-full")
	t.Setenv("AG_API_KEY_PEPPER", "0123456789abcdef0123456789abcdef")
	t.Setenv("AG_OPA_URL", "http://opa.internal:8181")
	if _, err := Load(); err == nil { t.Fatal("expected production to require HTTPS for OPA") }
}
func TestProductionAcceptsVerifiedDependencies(t *testing.T) {
	t.Setenv("AG_ENV", "production")
	t.Setenv("AG_DATABASE_URL", "postgres://agentguard:secret@db.example/agentguard?sslmode=verify-full")
	t.Setenv("AG_API_KEY_PEPPER", "0123456789abcdef0123456789abcdef")
	t.Setenv("AG_OPA_URL", "https://opa.example")
	if _, err := Load(); err != nil { t.Fatalf("expected verified production dependencies to pass: %v", err) }
}
