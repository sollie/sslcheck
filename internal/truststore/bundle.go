package truststore

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// EnvCacheDir replaces the OS user cache directory; sslcheck/ is still
	// appended. It lets a container point at a writable volume.
	EnvCacheDir = "SSLCHECK_CACHE_DIR"
	// EnvBundleURL overrides the cacert.pem download URL; the checksum is
	// fetched from the same URL with ".sha256" appended.
	EnvBundleURL = "SSLCHECK_BUNDLE_URL"

	// DefaultBundleURL is where the Mozilla bundle is published.
	DefaultBundleURL = "https://curl.se/ca/cacert.pem"
	// BundleFile is the cached bundle's name inside CacheDir.
	BundleFile = "cacert.pem"
	// MinCertificates is the fewest certificates a downloaded bundle may hold.
	MinCertificates = 100

	maxDownload = 16 << 20
)

// ErrNotNewer is returned by Update when the published bundle is no newer than
// the embedded one.
var ErrNotNewer = errors.New("trust store bundle is not newer than the embedded one")

var dateRE = regexp.MustCompile(`(?m)^## Certificate data from Mozilla as of:\s*(.+?)\s*$`)

// CacheDir returns the directory sslcheck keeps downloaded data in: the OS
// user cache directory (or EnvCacheDir) plus "sslcheck". It is not created.
func CacheDir(env map[string]string) (string, error) {
	base := env[EnvCacheDir]
	if base == "" {
		var err error
		if base, err = os.UserCacheDir(); err != nil {
			return "", fmt.Errorf("find cache directory: %w", err)
		}
	}
	return filepath.Join(base, "sslcheck"), nil
}

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

// UpdateResult describes a bundle stored by Update.
type UpdateResult struct {
	Path         string
	Date         time.Time
	Certificates int
}

// Update downloads the Mozilla bundle and its SHA-256, validates it and
// stores it in CacheDir. It checks that the checksum matches, that the bundle
// parses, that it holds at least MinCertificates and that it is newer than the
// embedded bundle. On any failure nothing is written and an existing cached
// bundle is left untouched. The checksum guards integrity, not authenticity.
func Update(ctx context.Context, env map[string]string, client *http.Client) (UpdateResult, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	url := env[EnvBundleURL]
	if url == "" {
		url = DefaultBundleURL
	}
	data, err := download(ctx, client, url)
	if err != nil {
		return UpdateResult{}, err
	}
	sumData, err := download(ctx, client, url+".sha256")
	if err != nil {
		return UpdateResult{}, err
	}
	var want string
	if f := strings.Fields(string(sumData)); len(f) > 0 {
		want = strings.ToLower(f[0])
	}
	got := sha256.Sum256(data)
	if _, err := hex.DecodeString(want); err != nil || len(want) != sha256.Size*2 {
		return UpdateResult{}, errors.New("published checksum is not a SHA-256 hex digest")
	}
	if want != hex.EncodeToString(got[:]) {
		return UpdateResult{}, errors.New("checksum mismatch: downloaded bundle does not match its published SHA-256")
	}
	b, err := parseBundle(data)
	if err != nil {
		return UpdateResult{}, fmt.Errorf("downloaded bundle rejected: %w", err)
	}
	if b.count < MinCertificates {
		return UpdateResult{}, fmt.Errorf("downloaded bundle has too few certificates (%d, need at least %d)", b.count, MinCertificates)
	}
	emb, err := embedded()
	if err != nil {
		return UpdateResult{}, err
	}
	if !b.date.After(emb.Date) {
		return UpdateResult{}, fmt.Errorf("%w: downloaded bundle is %s, embedded is %s", ErrNotNewer,
			b.date.UTC().Format(time.DateOnly), emb.Date.UTC().Format(time.DateOnly))
	}
	dir, err := CacheDir(env)
	if err != nil {
		return UpdateResult{}, err
	}
	path := filepath.Join(dir, BundleFile)
	if err := WriteFileAtomic(path, data); err != nil {
		return UpdateResult{}, err
	}
	return UpdateResult{Path: path, Date: b.date, Certificates: b.count}, nil
}

// WriteFileAtomic writes data to path via a temporary file in the same
// directory, creating the directory if needed. Other cache users such as the
// CT log list refresh should use it too.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp, 0o644) //nolint:gosec // cache data is not secret
	}
	if werr == nil {
		werr = os.Rename(tmp, path)
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write cache: %w", werr)
	}
	return nil
}

// Download fetches url with the same limits Update uses. Exported for the
// CT log list refresh.
func Download(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	return download(ctx, client, url)
}

func download(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	resp, err := client.Do(req) //nolint:gosec // URL is operator-configurable by design
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if len(data) > maxDownload {
		return nil, fmt.Errorf("download %s: larger than %d bytes", url, maxDownload)
	}
	return data, nil
}
