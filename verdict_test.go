package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sollie/sslcheck/internal/testutil"
)

// systemStoreWith returns an env whose system Trust store holds only the given roots.
func systemStoreWith(t *testing.T, roots ...*testutil.CA) map[string]string {
	t.Helper()
	var pemData []byte
	for _, r := range roots {
		pemData = append(pemData, r.PEM()...)
	}
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"SSLCHECK_TRUST_STORE": path}
}

func verdictLines(out string) (mozilla, system string) {
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(l, "Mozilla"):
			mozilla += l + "\n"
		case strings.Contains(l, "System"):
			system += l + "\n"
		}
	}
	return
}

func TestPrivateCAPassesSystemStoreAndFailsMozilla(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	inter := root.NewIntermediate(t, "Private Intermediate")
	leaf := inter.Issue(t, testutil.CertOpts{CommonName: "ok.test", DNSNames: []string{"ok.test"}})
	srv := testutil.StartTLS(t, leaf, &inter.Cert)

	code, out, errs := runCLI(t, systemStoreWith(t, root), "--no-color", "--sni", "ok.test", srv.Addr)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	moz, sys := verdictLines(out)
	if !strings.Contains(sys, "pass") {
		t.Errorf("system verdict should pass:\n%s", out)
	}
	for _, want := range []string{"Private Intermediate", "Private Root", "hostname match: yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(moz, "fail") || !strings.Contains(moz, "unknown authority") {
		t.Errorf("mozilla verdict should fail with unknown authority:\n%s", out)
	}
}

func TestVerdictFailureReasons(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	cases := map[string]struct {
		srv  *testutil.Server
		sni  string
		want string
	}{
		"expired": {
			srv:  testutil.StartTLS(t, root.Issue(t, testutil.Expired(testutil.CertOpts{CommonName: "a.test", DNSNames: []string{"a.test"}}))),
			sni:  "a.test",
			want: "expired",
		},
		"self-signed": {
			srv:  testutil.StartTLS(t, testutil.SelfSigned(t, testutil.CertOpts{CommonName: "b.test", DNSNames: []string{"b.test"}})),
			sni:  "b.test",
			want: "unknown authority",
		},
		"hostname mismatch": {
			srv:  testutil.StartTLS(t, root.Issue(t, testutil.CertOpts{CommonName: "c.test", DNSNames: []string{"c.test"}})),
			sni:  "other.test",
			want: "hostname mismatch",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errs := runCLI(t, systemStoreWith(t, root), "--no-color", "--sni", tc.sni, tc.srv.Addr)
			if code != 0 {
				t.Fatalf("exit %d, stderr: %s", code, errs)
			}
			_, sys := verdictLines(out)
			if !strings.Contains(sys, "fail") || !strings.Contains(sys, tc.want) {
				t.Errorf("system verdict should fail with %q:\n%s", tc.want, out)
			}
		})
	}
}

func TestHostnameCheckedAgainstTargetHostWithoutSNI(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	// 127.0.0.1 is the Target host; the certificate has no matching IP SAN.
	leaf := root.Issue(t, testutil.CertOpts{CommonName: "d.test", DNSNames: []string{"d.test"}})
	srv := testutil.StartTLS(t, leaf)

	_, out, _ := runCLI(t, systemStoreWith(t, root), "--no-color", srv.Addr)
	_, sys := verdictLines(out)
	if !strings.Contains(sys, "hostname mismatch") {
		t.Errorf("expected mismatch against Target host:\n%s", out)
	}
}

func TestExpiryWithinThirtyDaysIsWarning(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	leaf := root.Issue(t, testutil.CertOpts{CommonName: "e.test", DNSNames: []string{"e.test"}})
	srv := testutil.StartTLS(t, leaf)

	code, out, _ := runCLI(t, systemStoreWith(t, root), "--no-color", "--sni", "e.test", srv.Addr)
	if code != 0 {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "warning") || !strings.Contains(out, "expires in") {
		t.Errorf("expected expiry warning:\n%s", out)
	}
}

func TestStrictExitsTwoOnlyWhenAVerdictFails(t *testing.T) {
	root := testutil.NewCA(t, "Private Root")
	leaf := root.Issue(t, testutil.CertOpts{CommonName: "f.test", DNSNames: []string{"f.test"}})
	srv := testutil.StartTLS(t, leaf)
	env := systemStoreWith(t, root)

	if code, _, _ := runCLI(t, env, "--no-color", "--sni", "f.test", srv.Addr); code != 0 {
		t.Errorf("without --strict exit %d, want 0", code)
	}
	// Mozilla never trusts the private root, so --strict fails.
	if code, _, _ := runCLI(t, env, "--no-color", "--strict", "--sni", "f.test", srv.Addr); code != 2 {
		t.Errorf("with --strict exit %d, want 2", code)
	}
}
