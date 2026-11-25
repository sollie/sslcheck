package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/sollie/sslcheck/internal/render"
	"github.com/sollie/sslcheck/internal/scan"
	"github.com/spf13/pflag"
)

func main() {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, env))
}

// run is the testable entry point. It returns the process exit code:
// 0 when every Scan completed, 1 for connection and usage errors.
func run(args []string, stdout, stderr io.Writer, env map[string]string) int {
	fs := pflag.NewFlagSet("sslcheck", pflag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: sslcheck [flags] <host | host:port | https://host[:port]>...")
		fs.PrintDefaults()
	}
	var (
		sni     = fs.String("sni", "", "server name to send, overriding the Target host")
		timeout = fs.Duration("timeout", 5*time.Second, "timeout for connect and handshake")
		ipv4    = fs.BoolP("ipv4", "4", false, "connect over IPv4 only")
		ipv6    = fs.BoolP("ipv6", "6", false, "connect over IPv6 only")
		conc    = fs.Int("concurrency", 8, "maximum number of Targets scanned in parallel")
		noColor = fs.Bool("no-color", false, "disable colour output")
		format  = fs.StringP("format", "f", "pretty", "output format: pretty, json, yaml or toml")
		withPEM = fs.Bool("pem", false, "include each certificate as PEM")
	)
	if err := fs.Parse(args); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "sslcheck: %v\n", err)
		return 1
	}
	if fs.NArg() == 0 {
		_, _ = fmt.Fprintln(stderr, "sslcheck: no target given")
		fs.Usage()
		return 1
	}
	if *ipv4 && *ipv6 {
		_, _ = fmt.Fprintln(stderr, "sslcheck: --ipv4 and --ipv6 are mutually exclusive")
		return 1
	}
	if *conc < 1 {
		_, _ = fmt.Fprintln(stderr, "sslcheck: --concurrency must be at least 1")
		return 1
	}
	if !slices.Contains(render.Formats, *format) {
		_, _ = fmt.Fprintf(stderr, "sslcheck: unknown format %q (want %s)\n", *format, strings.Join(render.Formats, ", "))
		return 1
	}
	opts := scan.Options{Timeout: *timeout, SNI: *sni, Network: "tcp"}
	if *ipv4 {
		opts.Network = "tcp4"
	}
	if *ipv6 {
		opts.Network = "tcp6"
	}

	targets := make([]scan.Target, 0, fs.NArg())
	for _, a := range fs.Args() {
		t, err := scan.ParseTarget(a)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "sslcheck: %v\n", err)
			return 1
		}
		targets = append(targets, t)
	}

	results := scanAll(context.Background(), targets, opts, *conc)
	code := 0
	for _, r := range results {
		if r.Err != nil {
			code = 1
		}
	}
	if *format == "pretty" {
		render.PrettyPEM(stdout, results, useColor(stdout, env, *noColor), *withPEM)
	} else if err := render.Structured(stdout, render.NewReport(results, *withPEM), *format); err != nil {
		_, _ = fmt.Fprintf(stderr, "sslcheck: %v\n", err)
		return 1
	}
	return code
}

// scanAll scans targets with at most limit in flight; results keep input order.
func scanAll(ctx context.Context, targets []scan.Target, opts scan.Options, limit int) []scan.Result {
	results := make([]scan.Result, len(targets))
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i, t := range targets {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			results[i] = scan.Scan(ctx, t, opts)
		}()
	}
	wg.Wait()
	return results
}

func useColor(w io.Writer, env map[string]string, noColor bool) bool {
	if noColor {
		return false
	}
	if _, set := env["NO_COLOR"]; set {
		return false
	}
	if v := env["CLICOLOR_FORCE"]; v != "" && v != "0" {
		return true
	}
	f, ok := w.(*os.File)
	return ok && (isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()))
}
