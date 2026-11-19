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
