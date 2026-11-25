// Package truststore provides the Trust stores a Presented chain is verified
// against: the embedded Mozilla bundle and the system store.
package truststore

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"os"
)

// EnvSystemOverride names an environment variable that replaces the system
// Trust store with the PEM file it points to. It exists so tests can use a
// private CA as the "system" store; a public --trust-store flag is separate.
const EnvSystemOverride = "SSLCHECK_TRUST_STORE"

// MozillaBundleDate is the "Certificate data from Mozilla as of" date of the
// embedded cacert.pem, fetched from https://curl.se/ca/cacert.pem.
const MozillaBundleDate = "2026-11-05"

//go:embed cacert.pem
var mozillaPEM []byte

// Store is a named set of root certificates.
type Store struct {
	Name  string
	Roots *x509.CertPool
	// Unavailable marks a store that holds no roots at all, e.g. the system
	// store inside a FROM scratch container.
	Unavailable bool
}

// Mozilla returns the embedded Mozilla bundle.
func Mozilla() (Store, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(mozillaPEM) {
		return Store{}, fmt.Errorf("embedded Mozilla bundle contains no certificates")
	}
	return Store{Name: "Mozilla", Roots: pool}, nil
}

// System returns the operating system's store, or the PEM file named by
// EnvSystemOverride in env when set.
func System(env map[string]string) (Store, error) {
	if path := env[EnvSystemOverride]; path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied by design
		if err != nil {
			return Store{}, fmt.Errorf("read %s: %w", EnvSystemOverride, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return Store{}, fmt.Errorf("%s: no certificates in %s", EnvSystemOverride, path)
		}
		return Store{Name: "System", Roots: pool}, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return Store{}, fmt.Errorf("load system trust store: %w", err)
	}
	return Store{Name: "System", Roots: pool, Unavailable: pool.Equal(x509.NewCertPool())}, nil
}

// Default returns the Mozilla and system stores, in that order.
func Default(env map[string]string) ([]Store, error) {
	m, err := Mozilla()
	if err != nil {
		return nil, err
	}
	s, err := System(env)
	if err != nil {
		return nil, err
	}
	return []Store{m, s}, nil
}
