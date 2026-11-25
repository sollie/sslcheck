// Command refresh-trust-data updates the embedded Mozilla bundle and CT log
// list from their publishers. It applies exactly the validation of
// sslcheck --update-trust-store (checksum, parse, size, newer than embedded)
// and then replaces the embedded files in place. Run it from the repository
// root; it leaves the files untouched when nothing newer is published.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sollie/sslcheck/internal/ct"
	"github.com/sollie/sslcheck/internal/truststore"
)

const (
	bundleDest  = "internal/truststore/cacert.pem"
	logListDest = "internal/ct/log_list.json"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "refresh-trust-data: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	for _, p := range []string{bundleDest, logListDest} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("run from the repository root: %w", err)
		}
	}
	// Stage inside the working tree so no data is written outside it.
	stage, err := os.MkdirTemp(".", ".refresh-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	env := map[string]string{truststore.EnvCacheDir: stage}
	for _, k := range []string{truststore.EnvBundleURL, ct.EnvLogListURL} {
		if v := os.Getenv(k); v != "" {
			env[k] = v
		}
	}
	ctx := context.Background()

	switch res, err := truststore.Update(ctx, env, nil); {
	case errors.Is(err, truststore.ErrNotNewer):
		fmt.Println("trust store: already up to date")
	case err != nil:
		return fmt.Errorf("trust store: %w", err)
	default:
		if err := install(res.Path, bundleDest); err != nil {
			return err
		}
		fmt.Printf("trust store: updated to %s (%d certificates)\n", res.Date.UTC().Format("2006-01-02"), res.Certificates)
	}

	switch res, err := ct.Update(ctx, env, nil); {
	case errors.Is(err, ct.ErrNotNewer):
		fmt.Println("CT log list: already up to date")
	case err != nil:
		return fmt.Errorf("CT log list: %w", err)
	default:
		if err := install(res.Path, logListDest); err != nil {
			return err
		}
		fmt.Printf("CT log list: updated to %s (%d logs)\n", res.Date.UTC().Format("2006-01-02"), res.Logs)
	}
	return nil
}

func install(from, to string) error {
	data, err := os.ReadFile(filepath.Clean(from))
	if err != nil {
		return err
	}
	return truststore.WriteFileAtomic(to, data)
}
