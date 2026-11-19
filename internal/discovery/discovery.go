package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Deep-0610/agentguard/internal/model"
)

const (
	maxConfigBytes = 2 << 20
	maxTotalConfigBytes = 32 << 20
	maxConfigFiles = 10000
	maxWalkEntries = 100000
	maxWalkDepth = 32
)

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
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to scan symlink: %s", path)
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() { return nil, fmt.Errorf("not a regular file: %s", path) }
		return []string{path}, nil
	}
	var paths []string
	entries := 0
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > maxWalkEntries { return fmt.Errorf("directory contains more than %d entries", maxWalkEntries) }
		rel, relErr := filepath.Rel(path, p)
		if relErr != nil { return relErr }
		if depth := strings.Count(rel, string(os.PathSeparator)); depth > maxWalkDepth { return filepath.SkipDir }
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
		if configNames[strings.ToLower(d.Name())] {
			if len(paths) >= maxConfigFiles { return fmt.Errorf("more than %d MCP config files found", maxConfigFiles) }
			paths = append(paths, p)
		}
		return nil
	})
	return paths, err
}

func Load(paths []string) ([]model.Server, error) {
	var servers []model.Server
	var totalBytes int64
	for _, path := range paths {
		before, err := os.Lstat(path)
		if err != nil { return nil, err }
		if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing non-regular or symlink config: %s", path)
		}
		file, err := os.Open(path)
		if err != nil { return nil, err }
		opened, statErr := file.Stat()
		if statErr != nil { file.Close(); return nil, statErr }
		if !os.SameFile(before, opened) {
			file.Close()
			return nil, fmt.Errorf("config changed during scan: %s", path)
		}
		if opened.Size() > maxConfigBytes {
			file.Close()
			return nil, fmt.Errorf("config %s exceeds %d bytes", path, maxConfigBytes)
		}
		totalBytes += opened.Size()
		if totalBytes > maxTotalConfigBytes {
			file.Close()
			return nil, fmt.Errorf("total config input exceeds %d bytes", maxTotalConfigBytes)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
		closeErr := file.Close()
		if readErr != nil { return nil, readErr }
		if closeErr != nil { return nil, closeErr }
		if len(data) > maxConfigBytes { return nil, fmt.Errorf("config %s exceeds %d bytes", path, maxConfigBytes) }
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
			if err := json.Unmarshal(entry, &item); err != nil { return nil, fmt.Errorf("parse server %q in %s: %w", name, path, err) }
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
