package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/sollie/sslcheck/internal/render"
	"github.com/sollie/sslcheck/internal/scan"
	"github.com/sollie/sslcheck/internal/starttls"
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
		sni      = fs.String("sni", "", "server name to send, overriding the Target host")
		timeout  = fs.Duration("timeout", 5*time.Second, "timeout for connect and handshake")
		ipv4     = fs.BoolP("ipv4", "4", false, "connect over IPv4 only")
		ipv6     = fs.BoolP("ipv6", "6", false, "connect over IPv6 only")
		startTLS = fs.String("starttls", "", "upgrade with STARTTLS before the handshake: smtp, imap, pop3 or none (default: inferred from port)")
		noColor  = fs.Bool("no-color", false, "disable colour output")
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
	if !starttls.Valid(*startTLS) {
		_, _ = fmt.Fprintf(stderr, "sslcheck: unsupported --starttls protocol %q (want smtp, imap, pop3 or none)\n", *startTLS)
		return 1
	}
	opts := scan.Options{Timeout: *timeout, SNI: *sni, Network: "tcp", StartTLS: *startTLS}
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

	results := make([]scan.Result, 0, len(targets))
	code := 0
	for _, t := range targets {
		r := scan.Scan(context.Background(), t, opts)
		if r.Err != nil {
			code = 1
		}
		results = append(results, r)
	}
	render.Pretty(stdout, results, useColor(stdout, env, *noColor))
	return code
}

func useColor(w io.Writer, env map[string]string, noColor bool) bool {
	if noColor {
		return false
	}
	if _, set := env["NO_COLOR"]; set {
		return false
	}
	f, ok := w.(*os.File)
	return ok && (isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()))
}
