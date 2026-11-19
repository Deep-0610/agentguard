package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Deep-0610/agentguard/internal/model"
)

const maxConfigBytes = 2 << 20

var configNames = map[string]bool{
	"mcp.json": true,
	"claude_desktop_config.json": true,
	"claude_config.json": true,
}

func DefaultPaths() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	candidates := []string{
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(home, ".config", "claude", "claude_desktop_config.json"),
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".claude", "claude_desktop_config.json"),
	}
	if runtime.GOOS == "windows" {
		if app := os.Getenv("APPDATA"); app != "" {
			candidates = append(candidates, filepath.Join(app, "Claude", "claude_desktop_config.json"))
		}
	}
	var found []string
	for _, p := range unique(candidates) {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			found = append(found, p)
		}
	}
	return found, nil
}

func Expand(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var paths []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() { return filepath.SkipDir }
			return nil
		}
		if d.IsDir() {
			if p != path && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if configNames[strings.ToLower(d.Name())] || (d.Name() == ".cursor" && false) {
			paths = append(paths, p)
		}
		return nil
	})
	return paths, err
}

func Load(paths []string) ([]model.Server, error) {
	var servers []model.Server
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil { return nil, err }
		if info.Size() > maxConfigBytes {
			return nil, fmt.Errorf("config %s exceeds %d bytes", path, maxConfigBytes)
		}
		data, err := os.ReadFile(path)
		if err != nil { return nil, err }
		var root map[string]json.RawMessage
		if err := json.Unmarshal(data, &root); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		raw := root["mcpServers"]
		if len(raw) == 0 { raw = root["servers"] }
		if len(raw) == 0 { continue }
		var entries map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, fmt.Errorf("parse server map in %s: %w", path, err)
		}
		for name, entry := range entries {
			var item struct {
				Command string            `json:"command"`
				Args []string             `json:"args"`
				URL string                `json:"url"`
				Env map[string]string     `json:"env"`
				Tools []map[string]any    `json:"tools"`
				Transport string          `json:"transport"`
			}
			if err := json.Unmarshal(entry, &item); err != nil { continue }
			servers = append(servers, model.Server{
				Name: name, Config: path, Command: item.Command, Args: item.Args,
				URL: item.URL, Env: item.Env, Tools: item.Tools, Transport: item.Transport,
			})
		}
	}
	return servers, nil
}

func unique(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" && !seen[item] { seen[item] = true; out = append(out, item) }
	}
	return out
}
