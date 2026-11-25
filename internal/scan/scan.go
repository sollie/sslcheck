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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sollie/sslcheck/internal/ct"
	"github.com/sollie/sslcheck/internal/revocation"
	"github.com/sollie/sslcheck/internal/starttls"
	"github.com/sollie/sslcheck/internal/truststore"
	"github.com/sollie/sslcheck/internal/verify"
)

// Target is a host, port and optional SNI name to scan.
type Target struct {
	Host string
	Port int
	SNI  string
}

// Address returns host:port, bracketing IPv6 literals.
func (t Target) Address() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
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
	// Concurrency is the maximum number of Targets scanned in parallel; values below 1 mean 1.
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

// ScanAll scans targets with at most opts.Concurrency in flight; results keep input order.
func ScanAll(ctx context.Context, targets []Target, opts Options) []Result {
	results := make([]Result, len(targets))
	sem := make(chan struct{}, max(opts.Concurrency, 1))
	var wg sync.WaitGroup
	for i, t := range targets {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			// Admission stops: every unstarted Target gets an error result.
			results[i] = Result{Target: t, Err: ctx.Err()}
			continue
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			results[i] = scanOne(ctx, t, opts)
		}()
	}
	wg.Wait()
	return results
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
		opts.Timeout = 5 * time.Second
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

	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // scanner inspects untrusted chains by design, see ADR-0002
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       scanCipherSuites(),
	}
	if net.ParseIP(sni) == nil {
		cfg.ServerName = sni
	}
	proto := opts.StartTLS
	if proto == "" {
		proto = starttls.Infer(t.Port)
	}
	var tlsConn *tls.Conn
	if proto == "" || proto == starttls.None {
		dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
		conn, err := dialer.DialContext(ctx, network, t.Address())
		if err != nil {
			res.Err = err
			return res
		}
		tlsConn = conn.(*tls.Conn)
	} else {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, t.Address())
		if err != nil {
			res.Err = fmt.Errorf("STARTTLS %s: %w", proto, err)
			return res
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(dl)
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		if err := starttls.Upgrade(conn, proto); err != nil {
			_ = conn.Close()
			res.Err = err
			return res
		}
		tlsConn = tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			res.Err = err
			return res
		}
	}
	defer func() { _ = tlsConn.Close() }()

	state := tlsConn.ConnectionState()
	res.TLSVersion = tls.VersionName(state.Version)
	res.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	for _, c := range state.PeerCertificates {
		res.Certs = append(res.Certs, c)
		res.Chain = append(res.Chain, describe(c, at))
	}
	// Live lookups get their own --timeout budget; the staple needs no network.
	rctx, rcancel := context.WithTimeout(parent, opts.Timeout)
	defer rcancel()
	j := verify.Judge(rctx, verify.Evidence{
		Chain:        res.Certs,
		Name:         t.SNI,
		OCSPResponse: state.OCSPResponse,
		SCTs:         state.SignedCertificateTimestamps,
		CipherSuite:  state.CipherSuite,
		At:           at,
	}, verify.JudgeOptions{
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

// scanCipherSuites lists every suite Go implements, including those it
// excludes by default, so legacy Targets can still be inspected (ADR-0002).
// Only the scanning handshake uses it.
func scanCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
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
