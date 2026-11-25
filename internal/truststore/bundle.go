package truststore

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sollie/sslcheck/internal/refresh"
)

const (
	// EnvBundleURL overrides the cacert.pem download URL; the checksum is
	// fetched from the same URL with ".sha256" appended.
	EnvBundleURL = "SSLCHECK_BUNDLE_URL"

	// DefaultBundleURL is where the Mozilla bundle is published.
	DefaultBundleURL = "https://curl.se/ca/cacert.pem"
	// BundleFile is the cached bundle's name inside CacheDir.
	BundleFile = "cacert.pem"
	// MinCertificates is the fewest certificates a downloaded bundle may hold.
	MinCertificates = 100
)

var dateRE = regexp.MustCompile(`(?m)^## Certificate data from Mozilla as of:\s*(.+?)\s*$`)

type bundle struct {
	pool  *x509.CertPool
	count int
	date  time.Time
}

func bundleDate(data []byte) (time.Time, error) {
	m := dateRE.FindSubmatch(data)
	if m == nil {
		return time.Time{}, errors.New("no \"Certificate data from Mozilla as of\" date found")
	}
	t, err := time.Parse("Mon Jan _2 15:04:05 2006 MST", string(m[1]))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse bundle date %q: %w", m[1], err)
	}
	return t, nil
}

func parseBundle(data []byte) (bundle, error) {
	var b bundle
	b.pool = x509.NewCertPool()
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return bundle{}, fmt.Errorf("parse certificate: %w", err)
		}
		b.pool.AddCert(c)
		b.count++
	}
	if b.count == 0 {
		return bundle{}, errors.New("no certificates found")
	}
	var err error
	if b.date, err = bundleDate(data); err != nil {
		return bundle{}, err
	}
	return b, nil
}

// HTTPClient returns the client used for updates. When the system has no root
// certificates (for example in a scratch container) it trusts the embedded
// Mozilla bundle, so HTTPS downloads still work. SSL_CERT_FILE in env adds
// roots from that file. Redirects from HTTPS to HTTP are refused.
func HTTPClient(env map[string]string) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	pool, err := x509.SystemCertPool()
	if err != nil || pool.Equal(x509.NewCertPool()) {
		pool = nil
		if emb, err := Embedded(); err == nil {
			pool = emb.Roots
		}
	}
	if file := env["SSL_CERT_FILE"]; file != "" {
		if pem, err := os.ReadFile(file); err == nil { //nolint:gosec // operator-supplied roots
			if pool == nil {
				pool = x509.NewCertPool()
			}
			pool.AppendCertsFromPEM(pem)
		}
	}
	if pool != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect from HTTPS to %s", req.URL.Redacted())
			}
			return nil
		},
	}
}

// Update downloads the Mozilla bundle and its SHA-256 and stores it in the
// cache directory. Besides the generic checks of refresh.Update it checks that
// the checksum matches and that the bundle holds at least MinCertificates. The
// checksum guards integrity, not authenticity. A nil client uses HTTPClient.
func Update(ctx context.Context, env map[string]string, client *http.Client) (refresh.Result, error) {
	if client == nil {
		client = HTTPClient(env)
	}
	emb, err := Embedded()
	if err != nil {
		return refresh.Result{}, err
	}
	return refresh.Update(ctx, env, client, refresh.Dataset{
		Name:         "trust store bundle",
		File:         BundleFile,
		URLEnv:       EnvBundleURL,
		DefaultURL:   DefaultBundleURL,
		EmbeddedDate: emb.Date,
		Parse: func(data []byte) (refresh.Info, error) {
			b, err := parseBundle(data)
			if err == nil && b.count < MinCertificates {
				err = fmt.Errorf("too few certificates (%d, need at least %d)", b.count, MinCertificates)
			}
			return refresh.Info{Date: b.date, Count: b.count}, err
		},
		Check: checkBundleSum,
	})
}

func checkBundleSum(ctx context.Context, client *http.Client, url string, data []byte) error {
	sumData, err := refresh.Download(ctx, client, url+".sha256")
	if err != nil {
		return err
	}
	var want string
	if f := strings.Fields(string(sumData)); len(f) > 0 {
		want = strings.ToLower(f[0])
	}
	got := sha256.Sum256(data)
	if _, err := hex.DecodeString(want); err != nil || len(want) != sha256.Size*2 {
		return errors.New("published checksum is not a SHA-256 hex digest")
	}
	if want != hex.EncodeToString(got[:]) {
		return errors.New("checksum mismatch: downloaded bundle does not match its published SHA-256")
	}
	return nil
}
