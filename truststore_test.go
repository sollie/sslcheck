package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sollie/sslcheck/internal/testutil"
)

const (
	newerDateLine = "## Certificate data from Mozilla as of: Fri Dec  4 04:12:01 2099 GMT"
	olderDateLine = "## Certificate data from Mozilla as of: Mon Jan  5 04:12:01 2026 GMT"
)

var dateLineRE = regexp.MustCompile(`(?m)^## Certificate data from Mozilla as of:.*$`)

// bundleWith returns the embedded bundle with the given date line and extra roots appended.
func bundleWith(t *testing.T, dateLine string, extra ...*testutil.CA) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("internal", "truststore", "cacert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	out := dateLineRE.ReplaceAll(data, []byte(dateLine))
	for _, r := range extra {
		out = append(out, r.PEM()...)
	}
	return out
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]) + "  cacert.pem\n"
}

// updateEnv starts a fake download server and returns an env pointing at it and a temp cache dir.
func updateEnv(t *testing.T, bundle []byte, checksum string) (env map[string]string, cache string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ca/cacert.pem", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bundle) })
	mux.HandleFunc("/ca/cacert.pem.sha256", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(checksum)) })
	mux.HandleFunc("/ct/log_list.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(embeddedLogList(t)) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cache = t.TempDir()
	return map[string]string{
		"SSLCHECK_BUNDLE_URL":      srv.URL + "/ca/cacert.pem",
		"SSLCHECK_CT_LOG_LIST_URL": srv.URL + "/ct/log_list.json",
		"SSLCHECK_CACHE_DIR":       cache,
	}, cache
}

func privateServer(t *testing.T, root *testutil.CA) *testutil.Server {
	t.Helper()
	leaf := root.Issue(t, testutil.CertOpts{CommonName: "ok.test", DNSNames: []string{"ok.test"}})
	return testutil.StartTLS(t, leaf)
}

func TestEmbeddedBundleSourceAndDateAreReported(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	srv := privateServer(t, root)
	env := map[string]string{"SSLCHECK_CACHE_DIR": t.TempDir()}
	_, out, _ := runCLI(t, env, "--no-color", "--sni", "ok.test", srv.Addr)
	if !strings.Contains(out, "embedded") || !strings.Contains(out, "2026-11-05") {
		t.Errorf("report should name embedded source and date:\n%s", out)
	}
}

func TestUpdateStoresNewerBundleAndCacheWinsOverEmbedded(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	srv := privateServer(t, root)
	bundle := bundleWith(t, newerDateLine, root)
	env, cache := updateEnv(t, bundle, sum(bundle))

	code, _, errs := runCLI(t, env, "--update-trust-store")
	if code != 0 {
		t.Fatalf("update exit %d: %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(cache, "sslcheck", "cacert.pem")); err != nil {
		t.Fatalf("bundle not stored under sslcheck/: %v", err)
	}

	code, out, errs := runCLI(t, env, "--no-color", "--sni", "ok.test", srv.Addr)
	if code != 0 {
		t.Fatalf("scan exit %d: %s", code, errs)
	}
	moz, _ := verdictLines(out)
	if !strings.Contains(moz, "pass") {
		t.Errorf("cached bundle should be trusted:\n%s", out)
	}
	if !strings.Contains(out, "cache") || !strings.Contains(out, "2099-12-04") {
		t.Errorf("report should name cache source and date:\n%s", out)
	}
}

func TestUpdateRejectsBadBundlesAndStoresNothing(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	good := bundleWith(t, newerDateLine)
	tests := map[string]struct {
		bundle   []byte
		checksum string
		want     string
	}{
		"bad checksum":  {good, sum([]byte("other")), "checksum"},
		"unparseable":   {[]byte("not a pem"), sum([]byte("not a pem")), "certificates"},
		"too small":     {append([]byte(newerDateLine+"\n"), root.PEM()...), sum(append([]byte(newerDateLine+"\n"), root.PEM()...)), "too few"},
		"no date line":  {dateLineRE.ReplaceAll(good, nil), "", "date"},
		"empty sum":     {good, "\n", "checksum"},
		"malformed sum": {good, "zzzz  cacert.pem\n", "checksum"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.checksum == "" {
				tc.checksum = sum(tc.bundle)
			}
			env, cache := updateEnv(t, tc.bundle, tc.checksum)
			code, _, errs := runCLI(t, env, "--update-trust-store")
			if code != 1 || !strings.Contains(errs, tc.want) {
				t.Errorf("exit %d, stderr %q; want exit 1 mentioning %q", code, errs, tc.want)
			}
			if entries, _ := os.ReadDir(cache); len(entries) != 0 {
				t.Errorf("nothing should be stored, found %v", entries)
			}
		})
	}
}

func TestUpdateWithBundleNotNewerStillRefreshesCTAndExitsZero(t *testing.T) {
	for name, line := range map[string]string{
		"same":  "## Certificate data from Mozilla as of: Thu Nov  5 04:12:01 2026 GMT",
		"older": olderDateLine,
	} {
		t.Run(name, func(t *testing.T) {
			bundle := bundleWith(t, line)
			env, cache := updateEnv(t, bundle, sum(bundle))
			code, out, errs := runCLI(t, env, "--update-trust-store")
			if code != 0 {
				t.Fatalf("exit %d, stderr %q", code, errs)
			}
			if !strings.Contains(out, "Trust store is already up to date") {
				t.Errorf("stdout should say trust store is up to date: %q", out)
			}
			if _, err := os.Stat(filepath.Join(cache, "sslcheck", "cacert.pem")); err == nil {
				t.Error("bundle should not be stored")
			}
			if !strings.Contains(out, "CT log list") {
				t.Errorf("CT refresh should still run: %q", out)
			}
		})
	}
}

func TestRejectedUpdateKeepsPreviousCachedBundle(t *testing.T) {
	good := bundleWith(t, newerDateLine)
	env, cache := updateEnv(t, good, sum(good))
	if code, _, errs := runCLI(t, env, "--update-trust-store"); code != 0 {
		t.Fatalf("update: %s", errs)
	}
	bad, _ := updateEnv(t, good, "00  cacert.pem\n")
	bad["SSLCHECK_CACHE_DIR"] = cache
	if code, _, _ := runCLI(t, bad, "--update-trust-store"); code != 1 {
		t.Fatalf("bad update should fail")
	}
	got, err := os.ReadFile(filepath.Join(cache, "sslcheck", "cacert.pem"))
	if err != nil || string(got) != string(good) {
		t.Errorf("previous bundle should be intact (err %v)", err)
	}
}

func TestOlderCachedBundleLosesToEmbedded(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	srv := privateServer(t, root)
	cache := t.TempDir()
	dir := filepath.Join(cache, "sslcheck")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cacert.pem"), bundleWith(t, olderDateLine, root), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ := runCLI(t, map[string]string{"SSLCHECK_CACHE_DIR": cache}, "--no-color", "--sni", "ok.test", srv.Addr)
	moz, _ := verdictLines(out)
	if !strings.Contains(moz, "fail") || !strings.Contains(out, "embedded") {
		t.Errorf("embedded bundle should win over an older cache:\n%s", out)
	}
}

func TestExplicitTrustStoreOverridesEverything(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	srv := privateServer(t, root)
	path := filepath.Join(t.TempDir(), "mine.pem")
	if err := os.WriteFile(path, root.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	newer := bundleWith(t, newerDateLine)
	env, _ := updateEnv(t, newer, sum(newer))
	if code, _, errs := runCLI(t, env, "--update-trust-store"); code != 0 {
		t.Fatalf("update: %s", errs)
	}

	code, out, errs := runCLI(t, env, "--no-color", "--trust-store", path, "--sni", "ok.test", srv.Addr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	moz, sys := verdictLines(out)
	if moz != "" || sys != "" || strings.Count(out, "pass") != 1 {
		t.Errorf("expected a single verdict from the explicit file:\n%s", out)
	}
	if !strings.Contains(out, path) {
		t.Errorf("report should name the file:\n%s", out)
	}
}

func TestExplicitTrustStoreErrorsExitOne(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("nothing"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(t.TempDir(), "missing.pem"), empty} {
		if code, _, errs := runCLI(t, nil, "--trust-store", p, "localhost:1"); code != 1 || !strings.Contains(errs, "trust store") {
			t.Errorf("%s: exit %d, stderr %q", p, code, errs)
		}
	}
}
