// Package scan connects to a Target without verification and captures the
// Presented chain (see ADR-0002).
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
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sollie/sslcheck/internal/ct"
	"github.com/sollie/sslcheck/internal/revocation"
	"github.com/sollie/sslcheck/internal/starttls"
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
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		// No port: bare host, possibly a bracketed or bare IPv6 literal.
		host, portStr = strings.Trim(raw, "[]"), ""
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
	// CTLogs, when set, is the log list SCTs are verified against.
	CTLogs *ct.LogList
}

// Certificate describes one certificate of the Presented chain.
type Certificate struct {
	Subject       string    `json:"subject"`
	SANs          []string  `json:"sans"`
	Issuer        string    `json:"issuer"`
	Serial        string    `json:"serial"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	SigAlgorithm  string    `json:"signature_algorithm"`
	KeyType       string    `json:"key_type"`
	KeyBits       int       `json:"key_bits"`
	SHA256        string    `json:"sha256_fingerprint"`
	PEM           string    `json:"pem"`
}

// Result is the outcome of scanning one Target.
type Result struct {
	Target     Target        `json:"target"`
	TLSVersion string        `json:"tls_version"`
	Chain      []Certificate `json:"chain"`
	// Certs is the Presented chain as parsed certificates, in the order received.
	Certs []*x509.Certificate `json:"-"`
	// Verdicts holds one Verdict per Trust store; filled by the caller via verify.
	Verdicts []verify.Verdict `json:"verdicts,omitempty"`
	// Revocation holds the Revocation status results; applied to Verdicts by the caller.
	Revocation []revocation.Result `json:"-"`
	// CT holds the SCTs found and their verification; nil when no log list was given.
	CT  *ct.Result `json:"-"`
	Err error      `json:"-"`
}

// Scan connects to t, completes the handshake without verifying it and
// returns the Presented chain in the order received.
func Scan(ctx context.Context, t Target, opts Options) Result {
	res := Result{Target: t}
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
	for _, c := range state.PeerCertificates {
		res.Certs = append(res.Certs, c)
		res.Chain = append(res.Chain, describe(c, time.Now()))
	}
	// Live lookups get their own --timeout budget; the staple needs no network.
	rctx, rcancel := context.WithTimeout(parent, opts.Timeout)
	defer rcancel()
	res.Revocation = revocation.Check(rctx, res.Certs, state.OCSPResponse, opts.Revocation, time.Now())
	if opts.CTLogs != nil {
		r := ct.Verify(*opts.CTLogs, res.Certs, state.SignedCertificateTimestamps, state.OCSPResponse, time.Now())
		res.CT = &r
	}
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
