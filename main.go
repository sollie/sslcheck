package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/sollie/sslcheck/internal/ct"
	"github.com/sollie/sslcheck/internal/refresh"
	"github.com/sollie/sslcheck/internal/render"
	"github.com/sollie/sslcheck/internal/scan"
	"github.com/sollie/sslcheck/internal/starttls"
	"github.com/sollie/sslcheck/internal/truststore"
	"github.com/spf13/pflag"
)

// version is set at release time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, env)
	stop()
	os.Exit(code)
}

// config is the validated result of parsing the command line.
type config struct {
	showVersion bool
	update      bool
	format      string
	pem         bool
	noColor     bool
	strict      bool
	trustFile   string
	targets     []scan.Target
	opts        scan.Options // everything except CTLogs and Stores, which need data
}

// run is the testable entry point. It returns the process exit code:
// 0 when every Scan completed, 1 for connection and usage errors, and 2 when
// --strict is given and any Verdict fails.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, env map[string]string) int {
	cfg, err := parseConfig(args, stderr)
	switch {
	case errors.Is(err, pflag.ErrHelp):
		return 0
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "sslcheck: %v\n", err)
		return 1
	}
	if cfg.showVersion {
		_, _ = fmt.Fprintf(stdout, "sslcheck %s\n", version)
		return 0
	}
	if cfg.update {
		return updateData(ctx, stdout, stderr, env)
	}
	return execute(ctx, cfg, stdout, stderr, env)
}

// parseConfig parses and validates args without loading any data; usage text
// goes to w.
func parseConfig(args []string, w io.Writer) (config, error) {
	fs := pflag.NewFlagSet("sslcheck", pflag.ContinueOnError)
	fs.SetOutput(w)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(w, "Usage: sslcheck [flags] <host | host:port | https://host[:port]>...")
		fs.PrintDefaults()
	}
	var (
		sni       = fs.String("sni", "", "server name to send, overriding the Target host")
		timeout   = fs.Duration("timeout", 5*time.Second, "timeout for connect and handshake")
		ipv4      = fs.BoolP("ipv4", "4", false, "connect over IPv4 only")
		ipv6      = fs.BoolP("ipv6", "6", false, "connect over IPv6 only")
		startTLS  = fs.String("starttls", "", "upgrade with STARTTLS before the handshake: smtp, imap, pop3 or none (default: inferred from port)")
		conc      = fs.Int("concurrency", 8, "maximum number of Targets scanned in parallel")
		noColor   = fs.Bool("no-color", false, "disable colour output")
		format    = fs.StringP("format", "f", "pretty", "output format: pretty, json, yaml or toml")
		withPEM   = fs.Bool("pem", false, "include each certificate as PEM")
		revoc     = fs.Bool("revocation", false, "also query live OCSP (CRL when no OCSP URL) for every certificate except the root")
		privRev   = fs.Bool("allow-private-revocation", false, "let --revocation reach loopback, link-local and cloud-metadata addresses (for internal PKI)")
		strict    = fs.Bool("strict", false, "exit 2 when any Trust store Verdict fails")
		trustFile = fs.String("trust-store", "", "PEM file of root certificates to verify against, overriding the Mozilla and system stores")
		update    = fs.Bool("update-trust-store", false, "download the latest Mozilla bundle and CT log list into the cache directory and exit")
		showVer   = fs.Bool("version", false, "print version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if *showVer || *update {
		return config{showVersion: *showVer, update: *update}, nil
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return config{}, errors.New("no target given")
	}
	if *ipv4 && *ipv6 {
		return config{}, errors.New("--ipv4 and --ipv6 are mutually exclusive")
	}
	if *conc < 1 {
		return config{}, errors.New("--concurrency must be at least 1")
	}
	if *timeout <= 0 {
		return config{}, errors.New("--timeout must be positive")
	}
	if !starttls.Valid(*startTLS) {
		return config{}, fmt.Errorf("unsupported --starttls protocol %q (want smtp, imap, pop3 or none)", *startTLS)
	}
	if !slices.Contains(render.Formats, *format) {
		return config{}, fmt.Errorf("unknown format %q (want %s)", *format, strings.Join(render.Formats, ", "))
	}
	network := "tcp"
	if *ipv4 {
		network = "tcp4"
	}
	if *ipv6 {
		network = "tcp6"
	}
	targets := make([]scan.Target, 0, fs.NArg())
	for _, a := range fs.Args() {
		t, err := scan.ParseTarget(a)
		if err != nil {
			return config{}, err
		}
		targets = append(targets, t)
	}
	return config{
		format: *format, pem: *withPEM, noColor: *noColor, strict: *strict, trustFile: *trustFile,
		targets: targets,
		opts: scan.Options{
			Timeout: *timeout, SNI: *sni, Network: network, StartTLS: *startTLS,
			Revocation: *revoc, AllowPrivateRevocation: *privRev, Concurrency: *conc,
		},
	}, nil
}

// execute loads data, scans every Target and prints the Report.
func execute(ctx context.Context, cfg config, stdout, stderr io.Writer, env map[string]string) int {
	logList, err := ct.Load(env)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sslcheck: %v\n", err)
		return 1
	}
	stores, err := truststore.Default(env, cfg.trustFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sslcheck: %v\n", err)
		return 1
	}
	opts := cfg.opts
	opts.CTLogs = &logList
	opts.Stores = stores
	results := scan.ScanAll(ctx, cfg.targets, opts)
	code := 0
	verdictFailed := false
	for _, r := range results {
		if r.Err != nil {
			code = 1
		}
		verdictFailed = verdictFailed || r.Failed()
	}
	var werr error
	if cfg.format == "pretty" {
		werr = render.PrettyPEM(stdout, results, colorLevel(stdout, env, cfg.noColor), cfg.pem)
	} else {
		werr = render.Structured(stdout, render.NewReport(results, cfg.pem), cfg.format)
	}
	if werr != nil {
		_, _ = fmt.Fprintf(stderr, "sslcheck: %v\n", werr)
		return 1
	}
	if cfg.strict && verdictFailed {
		return 2
	}
	return code
}

// updateData implements --update-trust-store.
func updateData(ctx context.Context, stdout, stderr io.Writer, env map[string]string) int {
	client := truststore.HTTPClient(env)
	res, err := truststore.Update(ctx, env, client)
	switch {
	case errors.Is(err, refresh.ErrNotNewer):
		_, _ = fmt.Fprintln(stdout, "Trust store is already up to date")
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "sslcheck: update trust store: %v\n", err)
		return 1
	default:
		_, _ = fmt.Fprintf(stdout, "Trust store updated: %d certificates, dated %s, stored in %s\n",
			res.Count, res.Date.UTC().Format(time.DateOnly), res.Path)
	}
	list, err := ct.Update(ctx, env, client)
	switch {
	case errors.Is(err, refresh.ErrNotNewer):
		_, _ = fmt.Fprintln(stdout, "CT log list is already up to date")
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "sslcheck: update CT log list: %v\n", err)
		return 1
	default:
		_, _ = fmt.Fprintf(stdout, "CT log list updated: %d logs, dated %s, stored in %s\n",
			list.Count, list.Date.UTC().Format(time.DateOnly), list.Path)
	}
	return 0
}

func colorLevel(w io.Writer, env map[string]string, noColor bool) render.ColorLevel {
	if noColor {
		return render.ColorNone
	}
	if _, set := env["NO_COLOR"]; set {
		return render.ColorNone
	}
	forced := env["CLICOLOR_FORCE"] != "" && env["CLICOLOR_FORCE"] != "0"
	if !forced {
		f, ok := w.(*os.File)
		if !ok || (!isatty.IsTerminal(f.Fd()) && !isatty.IsCygwinTerminal(f.Fd())) {
			return render.ColorNone
		}
	}
	if ct := strings.ToLower(env["COLORTERM"]); ct == "truecolor" || ct == "24bit" {
		return render.ColorTrue
	}
	return render.Color16
}
