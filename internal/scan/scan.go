// Package scan connects to Targets without verification, captures each
// Presented chain (see ADR-0002) and judges it into one Verdict per Trust store.
package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sollie/sslcheck/internal/ct"
	"github.com/sollie/sslcheck/internal/revocation"
	"github.com/sollie/sslcheck/internal/truststore"
	"github.com/sollie/sslcheck/internal/verify"
)

const defaultTimeout = 5 * time.Second

// Target is a host, port and optional SNI name to scan.
type Target struct {
	Host string
	Port int
	SNI  string
	// IP pins the Scan to one resolved address of Host; empty means dial Host.
	IP string
}

// Address returns host:port, bracketing IPv6 literals.
func (t Target) Address() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// dialAddress is the address to connect to: the pinned IP when set, else Address.
func (t Target) dialAddress() string {
	if t.IP == "" {
		return t.Address()
	}
	return net.JoinHostPort(t.IP, strconv.Itoa(t.Port))
}

// ParseTarget accepts host, host:port and https://host[:port].
func ParseTarget(s string) (Target, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return Target{}, fmt.Errorf("invalid target %q: %w", s, err)
		}
		if u.Scheme != "https" {
			return Target{}, fmt.Errorf("unsupported scheme %q in %q (only https)", u.Scheme, s)
		}
		raw = u.Host
	}
	host, portStr, err := splitHostPort(raw)
	if err != nil {
		return Target{}, fmt.Errorf("invalid target %q: %w", s, err)
	}
	if host == "" {
		return Target{}, fmt.Errorf("invalid target %q: missing host", s)
	}
	port := 443
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return Target{}, fmt.Errorf("invalid port %q in %q", portStr, s)
		}
	}
	return Target{Host: host, Port: port}, nil
}

// splitHostPort splits host[:port], accepting bracketed and bare IPv6 literals
// and rejecting anything ambiguous or malformed.
func splitHostPort(raw string) (host, port string, err error) {
	if strings.HasPrefix(raw, "[") {
		end := strings.Index(raw, "]")
		if end < 0 {
			return "", "", errors.New("missing closing bracket")
		}
		host, rest := raw[1:end], raw[end+1:]
		if rest == "" {
			return host, "", nil
		}
		port, ok := strings.CutPrefix(rest, ":")
		if !ok || port == "" {
			return "", "", errors.New("malformed port")
		}
		return host, port, nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		return raw, "", nil
	}
	if strings.ContainsAny(raw, "[]") {
		return "", "", errors.New("unexpected bracket")
	}
	host, port, found := strings.Cut(raw, ":")
	if !found {
		return raw, "", nil
	}
	if port == "" || strings.Contains(port, ":") {
		return "", "", errors.New("malformed port")
	}
	return host, port, nil
}

// Options control how a Scan connects.
type Options struct {
	Timeout time.Duration
	// Network is "tcp", "tcp4" or "tcp6".
	Network string
	// SNI overrides the server name; defaults to the Target host.
	SNI string
	// StartTLS is "smtp", "imap" or "pop3" to upgrade in-band before the
	// handshake, "none" to force implicit TLS, or "" to infer from the port.
	StartTLS string
	// AllIPs scans every address a hostname Target resolves to instead of the
	// one the OS picks. IP-literal Targets are scanned once.
	AllIPs bool
	// Revocation enables live OCSP/CRL lookups; the stapled response is
	// always checked.
	Revocation bool
	// AllowPrivateRevocation lets live lookups reach loopback, link-local and
	// metadata addresses, for internal PKI.
	AllowPrivateRevocation bool
	// CTLogs, when set, is the log list SCTs are verified against.
	CTLogs *ct.LogList
	// Stores are the Trust stores each Presented chain is verified against.
	Stores []truststore.Store
	// Concurrency is the maximum number of Scans run in parallel; values below 1 mean 1.
	Concurrency int
	// Now is the clock used for expiry, revocation and SCT checks; defaults to time.Now.
	Now func() time.Time
}

// Certificate describes one certificate of the Presented chain.
type Certificate struct {
	Subject       string
	SANs          []string
	Issuer        string
	Serial        string
	NotBefore     time.Time
	NotAfter      time.Time
	DaysRemaining int
	// Expired and ExpiresSoon use exact timestamps; DaysRemaining is for display only.
	Expired      bool
	ExpiresSoon  bool
	SigAlgorithm string
	KeyType      string
	KeyBits      int
	SHA256       string
	PEM          string
	// Revocation holds the Revocation status results for this certificate.
	Revocation []revocation.Result
}

// Result is the outcome of scanning one Target.
type Result struct {
	Target     Target
	TLSVersion string
	// CipherSuite is the negotiated cipher suite; WeakCipher is set when it is insecure or lacks forward secrecy.
	CipherSuite string
	WeakCipher  bool
	Chain       []Certificate
	// Certs is the Presented chain as parsed certificates, in the order received.
	Certs []*x509.Certificate
	// Verdicts holds one Verdict per Trust store, with revocation and CT findings
	// applied. It is always populated when Err is nil.
	Verdicts []verify.Verdict
	// CT holds the SCTs found and their verification; nil when no log list was given.
	CT  *ct.Result
	Err error
}

// Failed reports whether any Verdict failed. Unavailable Verdicts do not count.
func (r Result) Failed() bool {
	for _, v := range r.Verdicts {
		if !v.Pass && !v.Unavailable {
			return true
		}
	}
	return false
}

// ScanAll runs at most opts.Concurrency Scans at once; results keep input
// order. With opts.AllIPs a hostname Target yields one Result per resolved
// address, v4 before v6 and ascending, regardless of completion order.
func ScanAll(ctx context.Context, targets []Target, opts Options) []Result {
	groups := make([][]Result, len(targets))
	sem := make(chan struct{}, max(opts.Concurrency, 1))
	var wg sync.WaitGroup
	for i, t := range targets {
		if !acquire(ctx, sem) {
			// Admission stops: every unstarted Target gets an error result.
			groups[i] = []Result{{Target: t, Err: ctx.Err()}}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			groups[i] = scanTarget(ctx, t, opts, sem)
		}()
	}
	wg.Wait()
	var results []Result
	for _, g := range groups {
		results = append(results, g...)
	}
	return results
}

// acquire takes a slot in sem, or reports false once ctx is done.
func acquire(ctx context.Context, sem chan struct{}) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case sem <- struct{}{}:
		if ctx.Err() != nil {
			<-sem
			return false
		}
		return true
	case <-ctx.Done():
		return false
	}
}

// scanTarget scans t once, or once per resolved address under opts.AllIPs. It
// is entered holding one slot of sem and gives it back before returning.
func scanTarget(ctx context.Context, t Target, opts Options, sem chan struct{}) []Result {
	if !opts.AllIPs || net.ParseIP(t.Host) != nil {
		defer func() { <-sem }()
		return []Result{scanOne(ctx, t, opts)}
	}
	addrs, err := resolve(ctx, t.Host, opts)
	<-sem
	if err != nil {
		return []Result{{Target: t, Err: err}}
	}
	results := make([]Result, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		pinned := t
		pinned.IP = a.String()
		if !acquire(ctx, sem) {
			results[i] = Result{Target: pinned, Err: ctx.Err()}
			continue
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			results[i] = scanOne(ctx, pinned, opts)
		}()
	}
	wg.Wait()
	return results
}

// resolve returns the distinct addresses of host for opts.Network, v4 before
// v6 and ascending.
func resolve(ctx context.Context, host string, opts Options) ([]netip.Addr, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	network := "ip"
	switch opts.Network {
	case "tcp4":
		network = "ip4"
	case "tcp6":
		network = "ip6"
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	for i, a := range addrs {
		addrs[i] = a.Unmap()
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	return slices.Compact(addrs), nil
}

// scanOne connects to t, completes the handshake without verifying it,
// captures the Presented chain in the order received and judges it.
func scanOne(ctx context.Context, t Target, opts Options) Result {
	res := Result{Target: t}
	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}
	// One clock reading serves every stage of this Scan.
	at := clock()
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	network := opts.Network
	if network == "" {
		network = "tcp"
	}
	sni := opts.SNI
	if sni == "" {
		sni = t.Host
	}
	t.SNI = sni
	res.Target = t

	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	ev, err := connect(ctx, t, connectOptions{network: network, sni: sni, startTLS: opts.StartTLS}, at)
	if err != nil {
		res.Err = err
		return res
	}
	res.TLSVersion = ev.TLSVersion
	res.CipherSuite = tls.CipherSuiteName(ev.CipherSuite)
	for _, c := range ev.Chain {
		res.Certs = append(res.Certs, c)
		res.Chain = append(res.Chain, describe(c, at))
	}
	// Live lookups get their own --timeout budget; the staple needs no network.
	rctx, rcancel := context.WithTimeout(parent, opts.Timeout)
	defer rcancel()
	j := verify.Judge(rctx, ev, verify.JudgeOptions{
		Stores:                 opts.Stores,
		CTLogs:                 opts.CTLogs,
		Revocation:             opts.Revocation,
		AllowPrivateRevocation: opts.AllowPrivateRevocation,
	})
	for _, rv := range j.Revocation {
		res.Chain[rv.Cert].Revocation = append(res.Chain[rv.Cert].Revocation, rv)
	}
	res.WeakCipher = j.WeakCipher
	res.CT = j.CT
	res.Verdicts = j.Verdicts
	return res
}

func describe(c *x509.Certificate, now time.Time) Certificate {
	sans := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, c.EmailAddresses...)
	for _, u := range c.URIs {
		sans = append(sans, u.String())
	}
	sum := sha256.Sum256(c.Raw)
	kt, kb := keyInfo(c)
	return Certificate{
		Subject:       c.Subject.String(),
		SANs:          sans,
		Issuer:        c.Issuer.String(),
		Serial:        c.SerialNumber.Text(16),
		NotBefore:     c.NotBefore,
		NotAfter:      c.NotAfter,
		DaysRemaining: int(c.NotAfter.Sub(now).Hours() / 24),
		Expired:       now.After(c.NotAfter),
		ExpiresSoon:   verify.ExpiresSoon(c, now),
		SigAlgorithm:  c.SignatureAlgorithm.String(),
		KeyType:       kt,
		KeyBits:       kb,
		SHA256:        hex.EncodeToString(sum[:]),
		PEM:           string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
	}
}

func keyInfo(c *x509.Certificate) (string, int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return c.PublicKeyAlgorithm.String(), 0
}
