package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sollie/sslcheck/internal/testutil"
)

func embeddedLogList(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("internal", "ct", "log_list.json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func ctEnv(t *testing.T, logs ...*testutil.CTLog) map[string]string {
	t.Helper()
	return map[string]string{
		"SSLCHECK_CT_LOG_LIST": testutil.WriteLogList(t, logs...),
		"SSLCHECK_CACHE_DIR":   t.TempDir(),
	}
}

func trustFile(t *testing.T, root *testutil.CA) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(path, root.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEmbeddedSCTsAreVerifiedAndShown(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	a, b := testutil.NewCTLog(t, "Fake Log A"), testutil.NewCTLog(t, "Fake Log B")
	leaf := root.Issue(t, testutil.CertOpts{CommonName: "ct.test", DNSNames: []string{"ct.test"}, CTLogs: []*testutil.CTLog{a, b}})
	srv := testutil.StartTLS(t, leaf, &root.Cert)

	code, out, errs := runCLI(t, ctEnv(t, a, b), "--no-color", "--strict", "--trust-store", trustFile(t, root), "--sni", "ct.test", srv.Addr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"2 SCTs, 2 valid", "Fake Log A", "Fake Log B", "certificate", "valid"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no SCTs") || strings.Contains(out, "only ") {
		t.Errorf("unexpected CT warning:\n%s", out)
	}
}

func TestSCTsFromTLSExtensionAndStapledOCSP(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	a, b := testutil.NewCTLog(t, "Fake Log A"), testutil.NewCTLog(t, "Fake Log B")
	resp := testutil.StartResponder(t, root)
	leaf := root.Issue(t, testutil.CertOpts{CommonName: "ct.test", DNSNames: []string{"ct.test"}})
	staple := resp.StapleWithSCTs(t, leaf, b.SignX509(t, leaf))
	srv := testutil.StartTLSSCTs(t, staple, [][]byte{a.SignX509(t, leaf)}, leaf, &root.Cert)

	code, out, errs := runCLI(t, ctEnv(t, a, b), "--no-color", "-f", "json", "--sni", "ct.test", srv.Addr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	rep := decode(t, "json", out)
	r := rep.Results[0]
	if r.SCTCount == nil || *r.SCTCount != 2 || r.SCTValid == nil || *r.SCTValid != 2 {
		t.Fatalf("want 2 valid SCTs, got %+v", r)
	}
	sources := map[string]string{}
	for _, s := range r.SCTs {
		if !s.Valid || s.LogID == "" || s.Timestamp == "" {
			t.Errorf("bad SCT %+v", s)
		}
		sources[s.Source] = s.Log
	}
	if sources["tls-extension"] != "Fake Log A" || sources["ocsp"] != "Fake Log B" {
		t.Errorf("sources: %v", sources)
	}
}

func TestMissingOrFewSCTsWarnButNeverTripStrict(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	a := testutil.NewCTLog(t, "Fake Log A")
	rootFile := trustFile(t, root)
	for name, tc := range map[string]struct {
		opts testutil.CertOpts
		want string
	}{
		"none": {testutil.CertOpts{CommonName: "ct.test", DNSNames: []string{"ct.test"}}, "no SCTs"},
		"one":  {testutil.CertOpts{CommonName: "ct.test", DNSNames: []string{"ct.test"}, CTLogs: []*testutil.CTLog{a}}, "only 1 valid"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := testutil.StartTLS(t, root.Issue(t, tc.opts), &root.Cert)
			env := ctEnv(t, a)
			code, out, errs := runCLI(t, env, "--no-color", "--strict", "--trust-store", rootFile, "--sni", "ct.test", srv.Addr)
			if code != 0 {
				t.Fatalf("exit %d (strict must ignore CT warnings): %s\n%s", code, errs, out)
			}
			if !strings.Contains(out, "warning:") || !strings.Contains(out, tc.want) {
				t.Errorf("expected warning %q:\n%s", tc.want, out)
			}
		})
	}
}

func TestInvalidAndUnknownLogSCTsAreWarnings(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	known, unknown := testutil.NewCTLog(t, "Known Log"), testutil.NewCTLog(t, "Unknown Log")
	leaf := root.Issue(t, testutil.CertOpts{CommonName: "ct.test", DNSNames: []string{"ct.test"}})
	other := root.Issue(t, testutil.CertOpts{CommonName: "other.test", DNSNames: []string{"other.test"}})
	// One SCT is for a different certificate, one comes from a log that is not listed.
	srv := testutil.StartTLSSCTs(t, nil, [][]byte{known.SignX509(t, other), unknown.SignX509(t, leaf)}, leaf, &root.Cert)

	code, out, errs := runCLI(t, ctEnv(t, known), "--no-color", "--strict", "--sni", "ct.test", srv.Addr)
	if code == 1 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"signature does not verify", "not in the log list", "0 valid"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestUpdateRefreshesCTLogListAndCacheWinsOverEmbedded(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	srv := privateServer(t, root)
	log := testutil.NewCTLog(t, "Fresh Log")
	bundle := bundleWith(t, newerDateLine)
	env, cache := updateEnv(t, bundle, sum(bundle))

	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(testutil.LogListJSON(t, time.Now().Add(time.Hour), log))
	}))
	t.Cleanup(list.Close)
	env["SSLCHECK_CT_LOG_LIST_URL"] = list.URL

	code, out, errs := runCLI(t, env, "--update-trust-store")
	if code != 0 || !strings.Contains(out, "CT log list updated") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(cache, "sslcheck", "log_list.json")); err != nil {
		t.Fatalf("log list not cached: %v", err)
	}

	_, out, _ = runCLI(t, env, "--no-color", "--sni", "ok.test", srv.Addr)
	if !strings.Contains(out, "log list: cache") {
		t.Errorf("cached log list should win over embedded:\n%s", out)
	}
	_, out, _ = runCLI(t, map[string]string{"SSLCHECK_CACHE_DIR": t.TempDir()}, "--no-color", "--sni", "ok.test", srv.Addr)
	if !strings.Contains(out, "log list: embedded") {
		t.Errorf("embedded log list expected without cache:\n%s", out)
	}
}

func TestBadLogListUpdateFailsAndStoresNothing(t *testing.T) {
	bundle := bundleWith(t, newerDateLine)
	env, cache := updateEnv(t, bundle, sum(bundle))
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) }))
	t.Cleanup(bad.Close)
	env["SSLCHECK_CT_LOG_LIST_URL"] = bad.URL

	code, _, errs := runCLI(t, env, "--update-trust-store")
	if code != 1 || !strings.Contains(errs, "CT log list") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if _, err := os.Stat(filepath.Join(cache, "sslcheck", "log_list.json")); err == nil {
		t.Error("rejected list must not be stored")
	}
}

func TestEmbeddedSCTsVerifyWithOutOfOrderChain(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	inter := root.NewIntermediate(t, "Private Intermediate")
	a, b := testutil.NewCTLog(t, "Fake Log A"), testutil.NewCTLog(t, "Fake Log B")
	leaf := inter.Issue(t, testutil.CertOpts{CommonName: "ct.test", DNSNames: []string{"ct.test"}, CTLogs: []*testutil.CTLog{a, b}})
	srv := testutil.StartTLS(t, leaf, &root.Cert, &inter.Cert)

	_, out, errs := runCLI(t, ctEnv(t, a, b), "--no-color", "--trust-store", trustFile(t, root), "--sni", "ct.test", srv.Addr)
	if !strings.Contains(out, "2 SCTs, 2 valid") {
		t.Errorf("SCTs should verify; stderr %s:\n%s", errs, out)
	}
}

func TestOutOfRangeSCTTimestampIsReportedInvalid(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	log := testutil.NewCTLog(t, "Known Log")
	leaf := root.Issue(t, testutil.CertOpts{CommonName: "ct.test", DNSNames: []string{"ct.test"}})
	srv := testutil.StartTLSSCTs(t, nil, [][]byte{log.SignX509AtMillis(t, leaf, 1<<63+5)}, leaf, &root.Cert)

	code, out, errs := runCLI(t, ctEnv(t, log), "--no-color", "--sni", "ct.test", srv.Addr)
	if code == 1 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "0 valid") || !strings.Contains(out, "timestamp") {
		t.Errorf("wrapped timestamp should be invalid:\n%s", out)
	}
}
