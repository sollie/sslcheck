// Package httppolicy is the one outbound-HTTP policy shared by revocation
// lookups and Embedded data updates. It owns the redirect cap, the size limit,
// HTTP(S)-only redirects, the HTTPS-to-HTTP downgrade ban and trust roots,
// including the Embedded-roots fallback when the system pool is empty.
// Callers choose a named policy; destination blocking is a revocation-only
// policy.
package httppolicy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"syscall"
	"time"
)

// Policy configures a client. Use Revocation or Update rather than building
// one by hand.
type Policy struct {
	// MaxRedirects is the number of redirects followed.
	MaxRedirects int
	// Timeout bounds a whole request; zero leaves it to the context.
	Timeout time.Duration
	// BlockInternal refuses loopback, link-local and metadata destinations at
	// connection time.
	BlockInternal bool
	// EnvProxy honours the proxy environment variables.
	EnvProxy bool
	// FallbackRoots returns the roots HTTPS is verified against when the
	// system pool is empty, as in a scratch container image.
	FallbackRoots func() *x509.CertPool
	// RootsFile is a PEM file of extra trusted roots.
	RootsFile string
}

// Revocation is the policy for live OCSP and CRL lookups. Loopback, link-local
// and metadata destinations are refused unless allowPrivate is set.
func Revocation(allowPrivate bool, fallback func() *x509.CertPool) Policy {
	return Policy{MaxRedirects: 3, BlockInternal: !allowPrivate, FallbackRoots: fallback}
}

// Update is the policy for Embedded data updates. Private destinations, such
// as an internal mirror, are allowed. SSL_CERT_FILE in env adds trusted roots.
func Update(env map[string]string, fallback func() *x509.CertPool) Policy {
	return Policy{
		MaxRedirects:  9,
		Timeout:       30 * time.Second,
		EnvProxy:      true,
		FallbackRoots: fallback,
		RootsFile:     env["SSL_CERT_FILE"],
	}
}

// NewClient returns an HTTP client enforcing p.
func NewClient(p Policy) *http.Client {
	if p.EnvProxy && p.BlockInternal {
		// A proxy dials on our behalf, so the destination block cannot be enforced.
		panic("httppolicy: EnvProxy and BlockInternal cannot be combined")
	}
	var tr *http.Transport
	if p.EnvProxy {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		if p.BlockInternal {
			dialer.Control = refuseInternal
		}
		tr = &http.Transport{
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			DisableKeepAlives:   true,
		}
	}
	if pool := p.roots(); pool != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Timeout:   p.Timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > p.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", p.MaxRedirects)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect refused: unsupported scheme %q", req.URL.Scheme)
			}
			if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect from HTTPS to %s", req.URL.Redacted())
			}
			return nil
		},
	}
}

// roots returns the pool to verify against, or nil for the system default.
func (p Policy) roots() *x509.CertPool {
	var pool *x509.CertPool
	if systemPoolEmpty() {
		if p.FallbackRoots != nil {
			pool = p.FallbackRoots()
		}
	} else if p.RootsFile != "" {
		pool, _ = x509.SystemCertPool()
	}
	if p.RootsFile != "" {
		if pem, err := os.ReadFile(p.RootsFile); err == nil {
			if pool == nil {
				pool = x509.NewCertPool()
			}
			pool.AppendCertsFromPEM(pem)
		}
	}
	return pool
}

// systemPoolEmpty reports whether Go has no system roots to verify with.
// macOS and Windows verify through the platform, not a pool.
func systemPoolEmpty() bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return false
	}
	pool, err := x509.SystemCertPool()
	return err != nil || pool == nil || len(pool.Subjects()) == 0 //nolint:staticcheck // only the count is needed
}

var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("100.100.100.200"),
}

// refuseInternal runs at connection time, on the address actually dialled, so
// DNS answers and redirects cannot bypass it.
func refuseInternal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("refused: %q is not an IP address", host)
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || slices.Contains(metadataAddrs, addr) {
		return fmt.Errorf("refused: %s is a loopback, link-local or metadata address (see --allow-private-revocation)", addr)
	}
	return nil
}

// StatusError is returned for a non-200 response.
type StatusError struct {
	Code   int
	Status string
}

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d", e.Code) }

// SizeError is returned when a response exceeds the size limit.
type SizeError struct{ Limit int64 }

func (e *SizeError) Error() string {
	return fmt.Sprintf("response exceeds the %d byte limit", e.Limit)
}

// Fetch sends one request and returns the body of a 200 response, refusing
// anything over limit bytes with a *SizeError. Transport errors are returned
// unwrapped; a non-200 status is a *StatusError.
func Fetch(ctx context.Context, client *http.Client, method, url string, body []byte, contentType string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Code: resp.StatusCode, Status: resp.Status}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &SizeError{Limit: limit}
	}
	return data, nil
}
