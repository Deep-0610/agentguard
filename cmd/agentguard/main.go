package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Deep-0610/agentguard/internal/discovery"
	"github.com/Deep-0610/agentguard/internal/report"
	"github.com/Deep-0610/agentguard/internal/scanner"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Printf("agentguard %s\n", version)
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "agentguard:", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "AgentGuard - local-first AI agent and MCP security scanner")
	fmt.Fprintln(os.Stderr, "Usage: agentguard <scan|version>")
	fmt.Fprintln(os.Stderr, "  scan --path PATH | --discover [--format table|json|html|sarif] [--output FILE]")
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	path := fs.String("path", "", "file or directory to scan")
	discover := fs.Bool("discover", false, "scan common MCP configuration locations")
	format := fs.String("format", "table", "table, json, html, or sarif")
	output := fs.String("output", "", "write report to a file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*path == "") == !*discover {
		return fmt.Errorf("choose exactly one of --path or --discover")
	}
	var targets []string
	var err error
	if *discover {
		targets, err = discovery.DefaultPaths()
	} else {
		targets, err = discovery.Expand(*path)
	}
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no supported MCP configuration files found")
	}
	configs, err := discovery.Load(targets)
	if err != nil {
		return err
	}
	if len(configs) == 0 {
		return fmt.Errorf("no MCP server entries found in the supplied configuration files")
	}
	findings := scanner.Analyze(configs)
	data, err := report.Render(*format, configs, findings)
	if err != nil {
		return err
	}
	if *output != "" {
		return writeReport(*output, data, targets)
	}
	_, err = os.Stdout.Write(data)
	return err
}

func writeReport(path string, data []byte, inputs []string) error {
	outputPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	outputPath = filepath.Clean(outputPath)
	outputInfo, statErr := os.Lstat(outputPath)
	if statErr == nil {
		if outputInfo.Mode()&os.ModeSymlink != 0 || !outputInfo.Mode().IsRegular() {
			return fmt.Errorf("refusing to write report to symlink or non-regular file: %s", outputPath)
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	for _, input := range inputs {
		inputPath, err := filepath.Abs(input)
		if err != nil {
			return err
		}
		if filepath.Clean(inputPath) == outputPath {
			return fmt.Errorf("report output must not overwrite scanned input: %s", outputPath)
		}
		if outputInfo != nil {
			inputInfo, err := os.Stat(input)
			if err == nil && os.SameFile(outputInfo, inputInfo) {
				return fmt.Errorf("report output resolves to scanned input: %s", outputPath)
			}
		}
	}
	dir := filepath.Dir(outputPath)
	temp, err := os.CreateTemp(dir, ".agentguard-report-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, outputPath); err != nil {
		return fmt.Errorf("atomically replace report %s: %w", outputPath, err)
	}
	return nil
}
