package store

import (
	"crypto/hmac"
	"testing"
)

func TestKeyDigestUsesPepper(t *testing.T) {
	a:=keyDigest("secret",[]byte("pepper-a"))
	b:=keyDigest("secret",[]byte("pepper-b"))
	if hmac.Equal(a,b) { t.Fatal("different peppers must produce different key digests") }
	if !hmac.Equal(a,keyDigest("secret",[]byte("pepper-a"))) { t.Fatal("same key and pepper should be deterministic") }
}
func TestSlugify(t *testing.T) {
	cases:=map[string]string{"Acme Security, Inc.":"acme-security-inc","  A  B  ":"a-b","___":"","AgentGuard":"agentguard"}
	for input,want:=range cases { if got:=slugify(input);got!=want { t.Errorf("slugify(%q)=%q, want %q",input,got,want) } }
}
