// Package refresh keeps Embedded data (the Mozilla bundle and the CT log list)
// current: it downloads a published copy, validates it and stores it in the
// cache directory, and reads a cached copy back only when it is newer than the
// embedded one.
package refresh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sollie/sslcheck/internal/httppolicy"
)

// EnvCacheDir replaces the OS user cache directory; sslcheck/ is still
// appended. It lets a container point at a writable volume.
const EnvCacheDir = "SSLCHECK_CACHE_DIR"

const maxDownload = 16 << 20

// ErrNotNewer is returned by Update when the published copy is no newer than
// the newest valid installed copy (cached or embedded).
var ErrNotNewer = errors.New("is not newer than the installed copy")

// Info is what an adapter learns from parsing a dataset.
type Info struct {
	Date  time.Time
	Count int
}

// Dataset describes one kind of Embedded data. Each adapter supplies the
// parts that differ; Update owns the rest of the flow.
type Dataset struct {
	// Name is used in error messages, for example "trust store bundle".
	Name string
	// File is the cached copy's name inside CacheDir.
	File string
	// URLEnv overrides DefaultURL when set in the environment.
	URLEnv     string
	DefaultURL string
	// EmbeddedDate is the date of the copy compiled into the binary.
	EmbeddedDate time.Time
	// Parse validates data and reports its date and item count.
	Parse func(data []byte) (Info, error)
	// Check, when set, runs before Parse so untrusted data is authenticated
	// before it is interpreted, for example against a published checksum.
	Check func(ctx context.Context, client *http.Client, url string, data []byte) error
}

// Result describes a copy stored by Update.
type Result struct {
	Path  string
	Date  time.Time
	Count int
}

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

// Update downloads ds, validates it and stores it in CacheDir unless it is not
// newer than the best installed copy. On any failure
// nothing is written and an existing cached copy is left untouched. A nil
// client uses http.DefaultClient.
func Update(ctx context.Context, env map[string]string, client *http.Client, ds Dataset) (Result, error) {
	if client == nil {
		client = http.DefaultClient
	}
	url := env[ds.URLEnv]
	if url == "" {
		url = ds.DefaultURL
	}
	data, err := Download(ctx, client, url)
	if err != nil {
		return Result{}, err
	}
	if ds.Check != nil {
		if err := ds.Check(ctx, client, url, data); err != nil {
			return Result{}, err
		}
	}
	info, err := ds.Parse(data)
	if err != nil {
		return Result{}, fmt.Errorf("downloaded %s rejected: %w", ds.Name, err)
	}
	dir, err := CacheDir(env)
	if err != nil {
		return Result{}, err
	}
	path := filepath.Join(dir, ds.File)
	best, source := ds.EmbeddedDate, "embedded"
	if cached, err := os.ReadFile(path); err == nil { //nolint:gosec // path is under the cache dir
		if ci, err := ds.Parse(cached); err == nil && ci.Date.After(best) {
			best, source = ci.Date, "cached"
		}
	}
	if !info.Date.After(best) {
		return Result{}, fmt.Errorf("%s %w: downloaded is %s, %s is %s", ds.Name, ErrNotNewer,
			info.Date.UTC().Format(time.DateOnly), source, best.UTC().Format(time.DateOnly))
	}
	if err := WriteFileAtomic(path, data); err != nil {
		return Result{}, err
	}
	return Result{Path: path, Date: info.Date, Count: info.Count}, nil
}

// Cached returns the cached copy of file as parsed by parse, but only when it
// is newer than embedded. ok is false when there is no cache, it does not
// parse or it is not newer.
func Cached[T any](env map[string]string, file string, embedded time.Time, parse func([]byte) (T, time.Time, error)) (v T, path string, ok bool) {
	dir, err := CacheDir(env)
	if err != nil {
		return v, "", false
	}
	path = filepath.Join(dir, file)
	data, err := os.ReadFile(path) //nolint:gosec // path is under the cache dir
	if err != nil {
		return v, "", false
	}
	parsed, date, err := parse(data)
	if err != nil || !date.After(embedded) {
		return v, "", false
	}
	return parsed, path, true
}

// WriteFileAtomic writes data to path via a temporary file in the same
// directory, creating the directory if needed.
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

// Download fetches url, refusing anything over 16 MiB.
func Download(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	data, err := httppolicy.Fetch(ctx, client, http.MethodGet, url, nil, "", maxDownload)
	var se *httppolicy.StatusError
	var ze *httppolicy.SizeError
	switch {
	case errors.As(err, &se):
		return nil, fmt.Errorf("download %s: %s", url, se.Status)
	case errors.As(err, &ze):
		return nil, fmt.Errorf("download %s: larger than %d bytes", url, maxDownload)
	case err != nil:
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	return data, nil
}
