package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/build"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/input"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/output"
)

func main() {
	inputPath := flag.String("input", "", "Path to Tracee JSON input (NDJSON or JSON array)")
	outputPath := flag.String("output", "", "Path to write graph output (- or empty writes to stdout)")
	outputFormat := flag.String("format", output.FormatJSON, "Output format: json or table")
	windowSec := flag.Int("window-sec", 300, "IOC correlation window in seconds")
	workers := flag.Int("workers", 0, "Worker count for parallel stages (0 uses GOMAXPROCS)")
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
