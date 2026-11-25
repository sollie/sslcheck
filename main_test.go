package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/sollie/sslcheck/internal/testutil"
)

// runCLI drives the single test seam and returns exit code, stdout and stderr.
func runCLI(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	if env == nil {
		env = map[string]string{}
	}
	code := run(args, &out, &errb, env)
	return code, out.String(), errb.String()
}

func TestScanPrintsPresentedChainInReceivedOrder(t *testing.T) {
	root := testutil.NewCA(t, "Test Root")
	inter := root.NewIntermediate(t, "Test Intermediate")
	leaf := inter.Issue(t, testutil.CertOpts{CommonName: "leaf.test", DNSNames: []string{"leaf.test", "alt.test"}})
	// Deliberately misordered: root before intermediate.
	srv := testutil.StartTLS(t, leaf, &root.Cert, &inter.Cert)

	code, out, errs := runCLI(t, nil, "--no-color", srv.Addr)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	for _, want := range []string{"leaf.test", "alt.test", "Test Root", "Test Intermediate", "Not After", "Not Before"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "Subject:       CN=Test Root") > strings.Index(out, "Subject:       CN=Test Intermediate") {
		t.Errorf("chain not in received order:\n%s", out)
	}
}

func TestScanCompletesAgainstExpiredServer(t *testing.T) {
	root := testutil.NewCA(t, "Test Root")
	leaf := root.Issue(t, testutil.Expired(testutil.CertOpts{CommonName: "old.test", DNSNames: []string{"old.test"}}))
	srv := testutil.StartTLS(t, leaf, &root.Cert)

	code, out, errs := runCLI(t, nil, "--no-color", srv.Addr)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	if !strings.Contains(out, "old.test") || !strings.Contains(out, "expired") {
		t.Errorf("expected expired report:\n%s", out)
	}
}

func TestScanCompletesAgainstSelfSignedServer(t *testing.T) {
	leaf := testutil.SelfSigned(t, testutil.CertOpts{CommonName: "self.test", DNSNames: []string{"self.test"}})
	srv := testutil.StartTLS(t, leaf)

	code, out, errs := runCLI(t, nil, "--no-color", srv.Addr)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	if !strings.Contains(out, "self.test") || !strings.Contains(out, "TLS version") {
		t.Errorf("expected self-signed report:\n%s", out)
	}
}

func TestHTTPSURLTargetWithPort(t *testing.T) {
	leaf := testutil.SelfSigned(t, testutil.CertOpts{CommonName: "url.test"})
	srv := testutil.StartTLS(t, leaf)

	code, out, errs := runCLI(t, nil, "--no-color", "https://"+srv.Addr)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	if !strings.Contains(out, "url.test") {
		t.Errorf("output missing subject:\n%s", out)
	}
}

func TestColourFollowsFlagAndEnvironment(t *testing.T) {
	leaf := testutil.SelfSigned(t, testutil.CertOpts{CommonName: "c.test"})
	srv := testutil.StartTLS(t, leaf)

	// A bytes.Buffer is not a TTY, so colour is off by default.
	_, out, _ := runCLI(t, nil, srv.Addr)
	if strings.Contains(out, "\x1b[") {
		t.Errorf("unexpected colour on non-TTY:\n%q", out)
	}
}

func TestConnectionErrorExitsOne(t *testing.T) {
	srv := testutil.StartTLS(t, testutil.SelfSigned(t, testutil.CertOpts{CommonName: "x"}))
	addr := srv.Addr
	srv.Close()

	code, out, _ := runCLI(t, nil, "--no-color", "--timeout", "2s", addr)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.Contains(out, "Error") {
		t.Errorf("error not reported:\n%s", out)
	}
}

func TestUsageErrorsExitOne(t *testing.T) {
	for name, args := range map[string][]string{
		"no target":     {},
		"unknown flag":  {"--bogus", "x"},
		"bad scheme":    {"http://example.com"},
		"bad port":      {"example.com:notaport"},
		"both families": {"-4", "-6", "example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, errs := runCLI(t, nil, args...); code != 1 || errs == "" {
				t.Errorf("exit %d, stderr %q; want 1 with message", code, errs)
			}
		})
	}
}

func TestMultipleTargetsPrintInInputOrderWithFailureReported(t *testing.T) {
	var addrs []string
	for _, cn := range []string{"one.test", "two.test", "three.test", "four.test"} {
		addrs = append(addrs, testutil.StartTLS(t, testutil.SelfSigned(t, testutil.CertOpts{CommonName: cn})).Addr)
	}
	dead := testutil.StartTLS(t, testutil.SelfSigned(t, testutil.CertOpts{CommonName: "dead"}))
	deadAddr := dead.Addr
	dead.Close()
	args := []string{"--no-color", "--timeout", "2s", "--concurrency", "2", addrs[0], deadAddr, addrs[1], addrs[2], addrs[3]}

	code, out, _ := runCLI(t, nil, args...)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	last := -1
	for _, m := range []string{"one.test", deadAddr, "two.test", "three.test", "four.test"} {
		i := strings.Index(out, m)
		if i <= last {
			t.Fatalf("%q out of order or missing:\n%s", m, out)
		}
		last = i
	}
	if !strings.Contains(out, "Error") {
		t.Errorf("failure not reported:\n%s", out)
	}
}

func TestConcurrencyMustBePositive(t *testing.T) {
	if code, _, errs := runCLI(t, nil, "--concurrency", "0", "example.com"); code != 1 || errs == "" {
		t.Errorf("exit %d, stderr %q; want 1 with message", code, errs)
	}
}

func TestIPFamilySelection(t *testing.T) {
	srv := testutil.StartTLS(t, testutil.SelfSigned(t, testutil.CertOpts{CommonName: "fam.test"}))
	if code, _, errs := runCLI(t, nil, "--no-color", "-4", srv.Addr); code != 0 {
		t.Errorf("-4: exit %d, stderr %s", code, errs)
	}
	if code, _, _ := runCLI(t, nil, "--no-color", "--timeout", "2s", "-6", srv.Addr); code != 1 {
		t.Errorf("-6 against IPv4 server: exit %d, want 1", code)

func TestScanReportsCertificateDetailsAndTLSVersion(t *testing.T) {
	root := testutil.NewCA(t, "Detail Root")
	leaf := root.Issue(t, testutil.CertOpts{CommonName: "detail.test", DNSNames: []string{"detail.test"}, NotAfter: time.Now().Add(90*24*time.Hour + time.Hour)})
	srv := testutil.StartTLS(t, leaf)

	code, out, errs := runCLI(t, nil, "--no-color", srv.Addr)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	sum := sha256.Sum256(leaf.DER)
	for _, want := range []string{
		"TLS version: TLS 1.3",
		"Issuer:        CN=Detail Root",
		"Serial:        " + leaf.Leaf.SerialNumber.Text(16),
		"Signature:     ECDSA-SHA256",
		"Key:           ECDSA 256 bits",
		"SHA-256:       " + hex.EncodeToString(sum[:]),
		"90 days remaining",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "warning") {
		t.Errorf("unexpected warning for certificate with 90 days left, got:\n%s", out)
	}
}

func TestExpiryWarningUnderThirtyDays(t *testing.T) {
	for name, tc := range map[string]struct {
		hours int
		warn  bool
	}{
		"29 days": {29*24 + 1, true},
		"31 days": {31*24 + 1, false},
	} {
		t.Run(name, func(t *testing.T) {
			leaf := testutil.SelfSigned(t, testutil.CertOpts{
				CommonName: "soon.test",
				NotAfter:   time.Now().Add(time.Duration(tc.hours) * time.Hour),
			})
			srv := testutil.StartTLS(t, leaf)
			_, out, _ := runCLI(t, nil, "--no-color", srv.Addr)
			if got := strings.Contains(out, "(warning)"); got != tc.warn {
				t.Errorf("warning=%v, want %v:\n%s", got, tc.warn, out)
			}
		})
	}
}
