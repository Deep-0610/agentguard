package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteReportRejectsSymlinkDestination(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "important.txt")
	link := filepath.Join(dir, "report.json")
	if err := os.WriteFile(target, []byte("keep-this-data"), 0600); err != nil { t.Fatal(err) }
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" { t.Skipf("symlink unavailable: %v", err) }
		t.Fatal(err)
	}
	if err := writeReport(link, []byte("replacement"), nil); err == nil {
		t.Fatal("expected symlink destination to be rejected")
	}
	got, err := os.ReadFile(target)
	if err != nil { t.Fatal(err) }
	if string(got) != "keep-this-data" { t.Fatalf("symlink target was modified: %q", got) }
}

func TestWriteReportDoesNotOverwriteScannedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil { t.Fatal(err) }
	if err := writeReport(path, []byte("report"), []string{path}); err == nil {
		t.Fatal("expected scanned input overwrite to be rejected")
	}
	got, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(got) != "original" { t.Fatalf("input file was modified: %q", got) }
}

func TestWriteReportCreatesPrivateOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := writeReport(path, []byte("report-data"), nil); err != nil { t.Fatal(err) }
	info, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("expected mode 0600, got %o", info.Mode().Perm()) }
	got, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(got) != "report-data" { t.Fatalf("unexpected report content: %q", got) }
}
