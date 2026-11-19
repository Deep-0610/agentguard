package main

import (
	"flag"
	"fmt"
	"os"

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
	configs, err := discovery.Load(targets)
	if err != nil {
		return err
	}
	findings := scanner.Analyze(configs)
	data, err := report.Render(*format, configs, findings)
	if err != nil {
		return err
	}
	if *output != "" {
		return os.WriteFile(*output, data, 0600)
	}
	_, err = os.Stdout.Write(data)
	return err
}
