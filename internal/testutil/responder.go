package testutil

import (
	"crypto/rand"
	"crypto/x509"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Responder is a fake OCSP and CRL responder for one issuing CA.
type Responder struct {
	URL string // base URL; OCSP is served at /ocsp and the CRL at /crl

	ca      *CA
	srv     *httptest.Server
	hits    atomic.Int64
	mu      sync.Mutex
	revoked map[string]bool
}

// StartResponder starts a responder that signs for ca. It is closed when the test ends.
func StartResponder(t testing.TB, ca *CA) *Responder {
	t.Helper()
	r := &Responder{ca: ca, revoked: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/ocsp", r.serveOCSP)
	mux.HandleFunc("/crl", r.serveCRL)
	r.srv = httptest.NewServer(mux)
	r.URL = r.srv.URL
	t.Cleanup(r.srv.Close)
	return r
}

// OCSPURL is the URL to embed as a certificate's OCSP server.
func (r *Responder) OCSPURL() string { return r.URL + "/ocsp" }

// CRLURL is the URL to embed as a certificate's CRL distribution point.
func (r *Responder) CRLURL() string { return r.URL + "/crl" }

// Requests returns how many HTTP requests the responder has served.
func (r *Responder) Requests() int { return int(r.hits.Load()) }

// Revoke marks c as revoked in subsequent OCSP responses and CRLs.
func (r *Responder) Revoke(c *Cert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[c.Leaf.SerialNumber.String()] = true
}

// Close stops the responder, making it unreachable.
func (r *Responder) Close() { r.srv.Close() }

func (r *Responder) isRevoked(serial *big.Int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoked[serial.String()]
}

func (r *Responder) ocspResponse(serial *big.Int) []byte {
	tmpl := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: serial,
		ThisUpdate:   time.Now().Add(-time.Hour),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}
	if r.isRevoked(serial) {
		tmpl.Status = ocsp.Revoked
		tmpl.RevokedAt = time.Now().Add(-time.Minute)
	}
	der, err := ocsp.CreateResponse(r.ca.Leaf, r.ca.Leaf, tmpl, r.ca.Key)
	if err != nil {
		panic(err)
	}
	return der
}

// Staple returns an OCSP response for c suitable for stapling, reflecting its current status.
func (r *Responder) Staple(c *Cert) []byte { return r.ocspResponse(c.Leaf.SerialNumber) }

func (r *Responder) serveOCSP(w http.ResponseWriter, req *http.Request) {
	r.hits.Add(1)
	body, _ := io.ReadAll(req.Body)
	parsed, err := ocsp.ParseRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(r.ocspResponse(parsed.SerialNumber))
}

func (r *Responder) serveCRL(w http.ResponseWriter, _ *http.Request) {
	r.hits.Add(1)
	r.mu.Lock()
	var entries []x509.RevocationListEntry
	for s := range r.revoked {
		n, _ := new(big.Int).SetString(s, 10)
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: time.Now().Add(-time.Minute)})
	}
	r.mu.Unlock()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, r.ca.Leaf, r.ca.Key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(der)
}
