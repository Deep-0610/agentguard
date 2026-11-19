package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMCPServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	data := `{"mcpServers":{"docs":{"command":"node","args":["server.js"],"env":{"MODE":"test"}}}}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil { t.Fatal(err) }
	servers, err := Load([]string{path})
	if err != nil { t.Fatal(err) }
	if len(servers) != 1 || servers[0].Name != "docs" { t.Fatalf("unexpected servers: %#v", servers) }
}

func TestLoadRejectsSymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(target, []byte(`{"mcpServers":{}}`), 0600); err != nil { t.Fatal(err) }
	if err := os.Symlink(target, link); err != nil { t.Skipf("symlink unavailable: %v", err) }
	if _, err := Load([]string{link}); err == nil { t.Fatal("expected symlink config to be rejected") }
}

func TestLoadEnforcesAggregateInputBudget(t *testing.T) {
	dir := t.TempDir()
	padding := strings.Repeat("x", (maxConfigBytes*9)/10)
	path := filepath.Join(dir, "mcp.json")
	data := []byte(`{"padding":"` + padding + `","mcpServers":{}}`)
	if len(data) > maxConfigBytes { t.Fatal("test fixture exceeds per-file limit") }
	if err := os.WriteFile(path, data, 0600); err != nil { t.Fatal(err) }
	paths := make([]string, 18)
	for i := range paths { paths[i] = path }
	if _, err := Load(paths); err == nil { t.Fatal("expected aggregate input budget to be enforced") }
}

func TestLoadRejectsMalformedServerEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"bad":{"args":"not-an-array"}}}`), 0600); err != nil { t.Fatal(err) }
	if _, err := Load([]string{path}); err == nil { t.Fatal("expected malformed server entry to fail") }
}
