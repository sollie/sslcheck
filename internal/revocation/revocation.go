// Package revocation determines the Revocation status of the certificates in a
// Presented chain from a stapled OCSP response, live OCSP or a CRL.
package revocation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"slices"
	"syscall"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/sollie/sslcheck/internal/issuer"
)

// Status is the Revocation status of a certificate.
type Status string

// Revocation statuses. Unknown never fails a Verdict.
const (
	Good    Status = "good"
	Revoked Status = "revoked"
	Unknown Status = "unknown"
)

// Source is where a Status came from.
type Source string

// Revocation sources.
const (
	Staple Source = "staple"
	OCSP   Source = "ocsp"
	CRL    Source = "crl"
)

const (
	maxOCSPBytes = 1 << 20
	maxCRLBytes  = 16 << 20

	// MaxAge is how old a response or CRL without a next-update time may be
	// before it is reported as unknown.
	MaxAge = 7 * 24 * time.Hour
	// clockSkew is how far in the future a response may claim to be issued.
	clockSkew = 5 * time.Minute
)

// Result is the Revocation status of one certificate from one source.
type Result struct {
	// Cert is the index of the certificate in the Presented chain.
	Cert   int
	Status Status
	Source Source
	// Detail explains Unknown results and names the responder otherwise.
	Detail string
}

// Policy controls live lookups.
type Policy struct {
	// AllowPrivate permits loopback, link-local, metadata and other private
	// destinations; by default loopback, link-local and metadata addresses are
	// refused at connection time.
	AllowPrivate bool
	// FallbackRoots returns the roots HTTPS responders are verified against
	// when the system pool is empty, as in a scratch container image.
	FallbackRoots func() *x509.CertPool
}

// Check returns the stapled result for the leaf, if a staple was presented,
// and, when live is set, live OCSP (or CRL when there is no OCSP URL) results
// for every certificate except the root. Issuers are resolved with
// issuer.Find, using roots for the last presented certificate. Responses count
// only when authenticated by the issuer or a valid delegated responder.
// Live lookups honour ctx and policy.
func Check(ctx context.Context, chain []*x509.Certificate, staple []byte, live bool, policy Policy, roots []*x509.CertPool, now time.Time) []Result {
	var out []Result
	if len(chain) == 0 {
		return out
	}
	if len(staple) > 0 {
		out = append(out, checkStaple(chain, staple, roots, now))
	}
	if !live {
		return out
	}
	client := newClient(policy)
	for i, c := range chain {
		if isRoot(c) {
			continue
		}
		out = append(out, checkLive(ctx, client, i, c, issuer.Find(chain, i, roots, now), now))
	}
	return out
}

const maxRedirects = 3

func newClient(policy Policy) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !policy.AllowPrivate {
		dialer.Control = refuseInternal
	}
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
	}
	if policy.FallbackRoots != nil && systemPoolEmpty() {
		tr.TLSClientConfig = &tls.Config{RootCAs: policy.FallbackRoots(), MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect refused: unsupported scheme %q", req.URL.Scheme)
			}
			return nil
		},
	}
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

func isRoot(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil
}

func checkStaple(chain []*x509.Certificate, staple []byte, roots []*x509.CertPool, now time.Time) Result {
	r := Result{Cert: 0, Source: Staple}
	iss := issuer.Find(chain, 0, roots, now)
	if iss == nil {
		return unknown(r, "issuer not available to authenticate the stapled OCSP response")
	}
	return parseOCSP(r, staple, chain[0], iss, now, "stapled response")
}

// parseOCSP is the single validation path for stapled and live responses.
func parseOCSP(r Result, data []byte, c, iss *x509.Certificate, now time.Time, from string) Result {
	resp, err := ocsp.ParseResponseForCert(data, c, iss)
	if err != nil {
		return unknown(r, fmt.Sprintf("%s unusable: %v", from, err))
	}
	if err := checkResponder(resp.Certificate, iss, now); err != nil {
		return unknown(r, fmt.Sprintf("%s not authenticated: %v", from, err))
	}
	if err := checkFresh(resp.ThisUpdate, resp.NextUpdate, now); err != nil {
		return unknown(r, fmt.Sprintf("%s: %v", from, err))
	}
	return fromOCSP(r, resp, now, from)
}

// checkResponder accepts a delegated responder certificate only when it can
// sign OCSP responses and is valid at now. The signature chain to the issuer
// has already been checked by the OCSP parser.
func checkResponder(responder, iss *x509.Certificate, now time.Time) error {
	if responder == nil || bytes.Equal(responder.Raw, iss.Raw) {
		return nil
	}
	if !slices.Contains(responder.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return errors.New("responder certificate lacks the OCSP-signing usage")
	}
	if now.Before(responder.NotBefore) || now.After(responder.NotAfter) {
		return errors.New("responder certificate is not valid now")
	}
	return nil
}

// checkFresh rejects responses issued in the future and, without a
// next-update time, responses older than MaxAge.
func checkFresh(thisUpdate, nextUpdate, now time.Time) error {
	if thisUpdate.After(now.Add(clockSkew)) {
		return errors.New("issued in the future")
	}
	if nextUpdate.IsZero() && now.Sub(thisUpdate) > MaxAge {
		return errors.New("too old and has no next-update time")
	}
	return nil
}

func fromOCSP(r Result, resp *ocsp.Response, now time.Time, from string) Result {
	r.Detail = from
	switch resp.Status {
	case ocsp.Good:
		if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate) {
			return unknown(r, "OCSP response is out of date")
		}
		r.Status = Good
	case ocsp.Revoked:
		r.Status = Revoked
		r.Detail = fmt.Sprintf("%s: revoked at %s", from, resp.RevokedAt.UTC().Format(time.RFC3339))
	default:
		r.Status = Unknown
	}
	return r
}

func unknown(r Result, detail string) Result {
	r.Status, r.Detail = Unknown, detail
	return r
}

func checkLive(ctx context.Context, client *http.Client, idx int, c, iss *x509.Certificate, now time.Time) Result {
	r := Result{Cert: idx, Source: OCSP}
	if iss == nil || c.CheckSignatureFrom(iss) != nil {
		return unknown(r, "issuer not found in the Presented chain or Trust store")
	}
	var errs []error
	for _, u := range c.OCSPServer {
		res, err := queryOCSP(ctx, client, u, c, iss, now)
		if err == nil {
			return withSource(res, idx, OCSP)
		}
		errs = append(errs, err)
	}
	if len(c.OCSPServer) == 0 && len(c.CRLDistributionPoints) > 0 {
		r.Source = CRL
		for _, u := range c.CRLDistributionPoints {
			res, err := queryCRL(ctx, client, u, c, iss, now)
			if err == nil {
				return withSource(res, idx, CRL)
			}
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return unknown(r, "no OCSP or CRL URL in certificate")
	}
	return unknown(r, errors.Join(errs...).Error())
}

func withSource(r Result, idx int, s Source) Result {
	r.Cert, r.Source = idx, s
	return r
}

func fetch(ctx context.Context, client *http.Client, method, rawURL string, body []byte, contentType string, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%s: unsupported URL", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", rawURL, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rawURL, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: response exceeds the %d byte limit", rawURL, limit)
	}
	return data, nil
}

func queryOCSP(ctx context.Context, client *http.Client, u string, c, iss *x509.Certificate, now time.Time) (Result, error) {
	reqBody, err := ocsp.CreateRequest(c, iss, nil)
	if err != nil {
		return Result{}, err
	}
	data, err := fetch(ctx, client, http.MethodPost, u, reqBody, "application/ocsp-request", maxOCSPBytes)
	if err != nil {
		return Result{}, err
	}
	return parseOCSP(Result{}, data, c, iss, now, u), nil
}

func queryCRL(ctx context.Context, client *http.Client, u string, c, iss *x509.Certificate, now time.Time) (Result, error) {
	data, err := fetch(ctx, client, http.MethodGet, u, nil, "", maxCRLBytes)
	if err != nil {
		return Result{}, err
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", u, err)
	}
	if err := crl.CheckSignatureFrom(iss); err != nil {
		return Result{}, fmt.Errorf("%s: %w", u, err)
	}
	if err := checkFresh(crl.ThisUpdate, crl.NextUpdate, now); err != nil {
		return Result{Status: Unknown, Detail: fmt.Sprintf("%s: CRL %v", u, err)}, nil
	}
	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		return Result{Status: Unknown, Detail: u + ": CRL is out of date"}, nil
	}
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(c.SerialNumber) == 0 {
			return Result{Status: Revoked, Detail: fmt.Sprintf("%s: revoked at %s", u, e.RevocationTime.UTC().Format(time.RFC3339))}, nil
		}
	}
	return Result{Status: Good, Detail: u}, nil
}
