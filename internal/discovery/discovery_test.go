package discovery

import (
	"os"
	"path/filepath"
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
