// Package truststore provides the Trust stores a Presented chain is verified
// against: the embedded Mozilla bundle and the system store.
package truststore

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"os"
	"time"

	"github.com/sollie/sslcheck/internal/refresh"
)

// EnvSystemOverride names an environment variable that replaces the system
// Trust store with the PEM file it points to. It exists so tests can use a
// private CA as the "system" store; the public --trust-store flag is separate
// and overrides every store.
const EnvSystemOverride = "SSLCHECK_TRUST_STORE"

//go:embed cacert.pem
var mozillaPEM []byte

// Store is a named set of root certificates.
type Store struct {
	Name  string
	Roots *x509.CertPool
	// Source says where the roots came from, for example "embedded bundle".
	Source string
	// Date is when the roots were published; zero when unknown.
	Date time.Time
	// Unavailable marks a store that holds no roots at all, e.g. the system
	// store inside a FROM scratch container.
	Unavailable bool
}

// Description returns the source and date of the store for reports.
func (s Store) Description() string {
	if s.Date.IsZero() {
		return s.Source
	}
	return s.Source + ", " + s.Date.UTC().Format(time.DateOnly)
}

// Mozilla returns the Mozilla bundle: a cached copy in the cache directory
// when it is newer than the embedded one, otherwise the embedded bundle.
func Mozilla(env map[string]string) (Store, error) {
	emb, err := Embedded()
	if err != nil {
		return Store{}, err
	}
	parse := func(data []byte) (bundle, time.Time, error) {
		b, err := parseBundle(data)
		return b, b.date, err
	}
	if b, path, ok := refresh.Cached(env, BundleFile, emb.Date, parse); ok {
		return Store{Name: "Mozilla", Roots: b.pool, Source: "cache " + path, Date: b.date}, nil
	}
	return emb, nil
}

// Embedded returns the Mozilla bundle compiled into the binary.
func Embedded() (Store, error) {
	b, err := parseBundle(mozillaPEM)
	if err != nil {
		return Store{}, fmt.Errorf("embedded Mozilla bundle: %w", err)
	}
	return Store{Name: "Mozilla", Roots: b.pool, Source: "embedded bundle", Date: b.date}, nil
}

// File returns a store holding the roots in the PEM file at path, as given by
// --trust-store. Its date is the bundle's own date, or the file's mtime.
func File(path string) (Store, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied by design
	if err != nil {
		return Store{}, fmt.Errorf("read trust store: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return Store{}, fmt.Errorf("trust store %s: no certificates found", path)
	}
	date, _ := bundleDate(data)
	if date.IsZero() {
		if fi, err := os.Stat(path); err == nil {
			date = fi.ModTime()
		}
	}
	return Store{Name: "Custom", Roots: pool, Source: "file " + path, Date: date}, nil
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
		// A file without certificates models an empty system store, as in a
		// FROM scratch container.
		ok := pool.AppendCertsFromPEM(data)
		return Store{Name: "System", Roots: pool, Source: "file " + path, Unavailable: !ok}, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return Store{}, fmt.Errorf("load system trust store: %w", err)
	}
	return Store{Name: "System", Roots: pool, Source: "operating system", Unavailable: pool.Equal(x509.NewCertPool())}, nil
}

// Default returns the stores to verify against. A non-empty explicitFile
// overrides both the Mozilla and system stores; otherwise the result is the
// Mozilla store followed by the system store.
func Default(env map[string]string, explicitFile string) ([]Store, error) {
	if explicitFile != "" {
		f, err := File(explicitFile)
		if err != nil {
			return nil, err
		}
		return []Store{f}, nil
	}
	m, err := Mozilla(env)
	if err != nil {
		return nil, err
	}
	s, err := System(env)
	if err != nil {
		return nil, err
	}
	return []Store{m, s}, nil
}
