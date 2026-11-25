// Package revocation determines the Revocation status of the certificates in a
// Presented chain from a stapled OCSP response, live OCSP or a CRL.
package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"
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

// Check returns the stapled result for the leaf, if a staple was presented,
// and, when live is set, live OCSP (or CRL when there is no OCSP URL) results
// for every certificate except the root. Live lookups honour ctx.
func Check(ctx context.Context, chain []*x509.Certificate, staple []byte, live bool, now time.Time) []Result {
	var out []Result
	if len(chain) == 0 {
		return out
	}
	if len(staple) > 0 {
		out = append(out, checkStaple(chain, staple, now))
	}
	if !live {
		return out
	}
	client := &http.Client{}
	for i, c := range chain {
		if isRoot(c) {
			continue
		}
		var issuer *x509.Certificate
		if i+1 < len(chain) {
			issuer = chain[i+1]
		}
		out = append(out, checkLive(ctx, client, i, c, issuer, now))
	}
	return out
}

func isRoot(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil
}

func checkStaple(chain []*x509.Certificate, staple []byte, now time.Time) Result {
	var issuer *x509.Certificate
	if len(chain) > 1 {
		issuer = chain[1]
	}
	r := Result{Cert: 0, Source: Staple}
	resp, err := ocsp.ParseResponseForCert(staple, chain[0], issuer)
	if err != nil {
		return unknown(r, fmt.Sprintf("stapled OCSP response unusable: %v", err))
	}
	return fromOCSP(r, resp, now, "stapled response")
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

func checkLive(ctx context.Context, client *http.Client, idx int, c, issuer *x509.Certificate, now time.Time) Result {
	r := Result{Cert: idx, Source: OCSP}
	if issuer == nil || c.CheckSignatureFrom(issuer) != nil {
		return unknown(r, "issuer not in the Presented chain")
	}
	var errs []error
	for _, u := range c.OCSPServer {
		res, err := queryOCSP(ctx, client, u, c, issuer, now)
		if err == nil {
			return withSource(res, idx, OCSP)
		}
		errs = append(errs, err)
	}
	if len(c.OCSPServer) == 0 {
		r.Source = CRL
		for _, u := range c.CRLDistributionPoints {
			res, err := queryCRL(ctx, client, u, c, issuer, now)
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rawURL, err)
	}
	return data, nil
}

func queryOCSP(ctx context.Context, client *http.Client, u string, c, issuer *x509.Certificate, now time.Time) (Result, error) {
	reqBody, err := ocsp.CreateRequest(c, issuer, nil)
	if err != nil {
		return Result{}, err
	}
	data, err := fetch(ctx, client, http.MethodPost, u, reqBody, "application/ocsp-request", maxOCSPBytes)
	if err != nil {
		return Result{}, err
	}
	resp, err := ocsp.ParseResponseForCert(data, c, issuer)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", u, err)
	}
	return fromOCSP(Result{}, resp, now, u), nil
}

func queryCRL(ctx context.Context, client *http.Client, u string, c, issuer *x509.Certificate, now time.Time) (Result, error) {
	data, err := fetch(ctx, client, http.MethodGet, u, nil, "", maxCRLBytes)
	if err != nil {
		return Result{}, err
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", u, err)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return Result{}, fmt.Errorf("%s: %w", u, err)
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
