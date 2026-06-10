package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/build"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/input"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/output"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/pcap"
)

type cidrFlag []string

func (f *cidrFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *cidrFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*f = append(*f, value)
	return nil
}

func main() {
	inputPath := flag.String("input", "", "Path to Tracee JSON input (NDJSON or JSON array)")
	artifactsPath := flag.String("artifacts", "", "Optional path to artifacts.zip or extracted artifacts directory from Tracee --artifacts file-write")
	outputPath := flag.String("output", "", "Path to write graph output (- or empty writes to stdout)")
	outputFormat := flag.String("format", output.FormatJSON, "Output format: json or table")
	windowSec := flag.Int("window-sec", 300, "IOC correlation window in seconds")
	workers := flag.Int("workers", 0, "Worker count for parallel stages (0 uses GOMAXPROCS)")
	pcapPath := flag.String("pcap", "", "Optional path to a tcpdump pcap/pcapng file for IOC network enrichment")
	mitmPath := flag.String("mitm", "", "Optional path to mitm_proxy.jsonl for IOC HTTP enrichment")
	var excludeCIDR cidrFlag
	flag.Var(&excludeCIDR, "exclude-cidr", "Additional internal CIDR to exclude (repeatable)")
	flag.Parse()

	if *inputPath == "" {
		fmt.Fprintln(os.Stderr, "error: -input is required")
		os.Exit(2)
	}

	in, err := os.Open(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open input: %v\n", err)
		os.Exit(1)
	}
	defer in.Close()

	events, err := input.ReadEventsWithOptions(in, input.ParseOptions{Workers: *workers})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse input: %v\n", err)
		os.Exit(1)
	}

	opts := model.DefaultBuildOptions()
	opts.CorrelationWindow = time.Duration(*windowSec) * time.Second
	opts.Workers = *workers
	graphOutput := build.FromEvents(events, opts)

	graphOutput, err = build.EnrichPayloads(graphOutput, *artifactsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: enrich payloads: %v\n", err)
		os.Exit(1)
	}

	excludeCIDRs, err := parseExcludeCIDRs(excludeCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse exclude-cidr: %v\n", err)
		os.Exit(2)
	}

	graphOutput, err = build.EnrichFromPcap(graphOutput, *pcapPath, opts.CorrelationWindow, excludeCIDRs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: enrich pcap: %v\n", err)
		os.Exit(1)
	}

	graphOutput, err = build.EnrichFromMitm(graphOutput, *mitmPath, opts.CorrelationWindow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: enrich mitm: %v\n", err)
		os.Exit(1)
	}

	encoded, err := output.Encode(*outputFormat, graphOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: encode output: %v\n", err)
		os.Exit(1)
	}

	if *outputPath == "" || *outputPath == "-" {
		if _, err := os.Stdout.Write(encoded); err != nil {
			fmt.Fprintf(os.Stderr, "error: write stdout: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := os.WriteFile(*outputPath, encoded, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write output: %v\n", err)
		os.Exit(1)
	}
}

func parseExcludeCIDRs(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, nil
	}
	return pcap.ParseCIDRs(values)
}
