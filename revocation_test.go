package main

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/sollie/sslcheck/internal/testutil"
)

type revFixture struct {
	root, inter *testutil.CA
	leaf        *testutil.Cert
	interResp   *testutil.Responder // signs for inter, answers for the leaf
	rootResp    *testutil.Responder // signs for root, answers for inter
	env         map[string]string
}

func newRevFixture(t *testing.T, leafOpts testutil.CertOpts) *revFixture {
	t.Helper()
	f := &revFixture{}
	f.root = testutil.NewCA(t, "Rev Root")
	f.rootResp = testutil.StartResponder(t, f.root)
	f.inter = f.root.NewIntermediateWith(t, testutil.CertOpts{
		CommonName: "Rev Intermediate",
		OCSPServer: []string{f.rootResp.OCSPURL()},
	})
	f.interResp = testutil.StartResponder(t, f.inter)
	leafOpts.CommonName, leafOpts.DNSNames = "ok.test", []string{"ok.test"}
	if leafOpts.OCSPServer == nil && leafOpts.CRLDistributionPoints == nil {
		leafOpts.OCSPServer = []string{f.interResp.OCSPURL()}
	}
	f.leaf = f.inter.Issue(t, leafOpts)
	f.env = systemStoreWith(t, f.root)
	return f
}

func (f *revFixture) systemVerdict(t *testing.T, out string) string {
	t.Helper()
	_, sys := verdictLines(out)
	if sys == "" {
		t.Fatalf("no system verdict in:\n%s", out)
	}
	return sys
}

func TestStapledRevokedFailsVerdictWithoutNetworkTraffic(t *testing.T) {
	f := newRevFixture(t, testutil.CertOpts{})
	f.interResp.Revoke(f.leaf)
	srv := testutil.StartTLSStapled(t, f.interResp.Staple(f.leaf), f.leaf, &f.inter.Cert)
	before := f.interResp.Requests() + f.rootResp.Requests()

	code, out, errs := runCLI(t, f.env, "--no-color", "--sni", "ok.test", srv.Addr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if sys := f.systemVerdict(t, out); !strings.Contains(sys, "fail") || !strings.Contains(sys, "revoked") {
		t.Errorf("system verdict should fail as revoked:\n%s", out)
	}
	if got := f.interResp.Requests() + f.rootResp.Requests(); got != before {
		t.Errorf("stapled check made %d network requests", got-before)
	}
}

func TestStapledGoodPasses(t *testing.T) {
	f := newRevFixture(t, testutil.CertOpts{})
	srv := testutil.StartTLSStapled(t, f.interResp.Staple(f.leaf), f.leaf, &f.inter.Cert)

	_, out, _ := runCLI(t, f.env, "--no-color", "--sni", "ok.test", srv.Addr)
	if sys := f.systemVerdict(t, out); !strings.Contains(sys, "pass") {
		t.Errorf("system verdict should pass:\n%s", out)
	}
	if !strings.Contains(out, "good (staple)") {
		t.Errorf("output should report the staple as good:\n%s", out)
	}
}

func TestLiveLookupsOnlyWithRevocationFlag(t *testing.T) {
	f := newRevFixture(t, testutil.CertOpts{})
	f.interResp.Revoke(f.leaf)
	srv := testutil.StartTLS(t, f.leaf, &f.inter.Cert, &f.root.Cert)

	_, out, _ := runCLI(t, f.env, "--no-color", "--sni", "ok.test", srv.Addr)
	if n := f.interResp.Requests() + f.rootResp.Requests(); n != 0 {
		t.Fatalf("lookups without --revocation: %d", n)
	}
	if sys := f.systemVerdict(t, out); !strings.Contains(sys, "pass") {
		t.Errorf("revocation unchecked, verdict should pass:\n%s", out)
	}

	_, out, _ = runCLI(t, f.env, "--no-color", "--revocation", "--sni", "ok.test", srv.Addr)
	if sys := f.systemVerdict(t, out); !strings.Contains(sys, "revoked") {
		t.Errorf("live lookup should fail the verdict as revoked:\n%s", out)
	}
	// One lookup each for leaf and intermediate; the presented root is skipped.
	if f.interResp.Requests() != 1 || f.rootResp.Requests() != 1 {
		t.Errorf("requests: leaf %d, intermediate %d; want 1 each", f.interResp.Requests(), f.rootResp.Requests())
	}
}

func TestUnreachableResponderIsUnknownAndOnlyWarns(t *testing.T) {
	f := newRevFixture(t, testutil.CertOpts{})
	f.interResp.Close()
	srv := testutil.StartTLS(t, f.leaf, &f.inter.Cert)

	code, out, errs := runCLI(t, f.env, "--no-color", "--strict", "--revocation", "--timeout", "2s", "--sni", "ok.test", srv.Addr)
	if code == 1 {
		t.Fatalf("exit 1: %s", errs)
	}
	sys := f.systemVerdict(t, out)
	if !strings.Contains(sys, "pass") {
		t.Errorf("unknown revocation must not fail the verdict:\n%s", out)
	}
	if !strings.Contains(out, "unknown") || !strings.Contains(out, "warning:") {
		t.Errorf("expected unknown status and a warning:\n%s", out)
	}
}

func TestCRLFallbackWhenNoOCSPURL(t *testing.T) {
	f := newRevFixture(t, testutil.CertOpts{})
	// Reissue the leaf with only a CRL distribution point.
	f.leaf = f.inter.Issue(t, testutil.CertOpts{CommonName: "ok.test", DNSNames: []string{"ok.test"}, CRLDistributionPoints: []string{f.interResp.CRLURL()}})
	f.interResp.Revoke(f.leaf)
	srv := testutil.StartTLS(t, f.leaf, &f.inter.Cert)

	_, out, _ := runCLI(t, f.env, "--no-color", "--revocation", "--sni", "ok.test", srv.Addr)
	if sys := f.systemVerdict(t, out); !strings.Contains(sys, "revoked") {
		t.Errorf("CRL should mark the leaf revoked:\n%s", out)
	}
	if !strings.Contains(out, "revoked (crl)") {
		t.Errorf("source should be crl:\n%s", out)
	}
}

func TestRevocationInStructuredOutput(t *testing.T) {
	f := newRevFixture(t, testutil.CertOpts{})
	srv := testutil.StartTLSStapled(t, f.interResp.Staple(f.leaf), f.leaf, &f.inter.Cert)

	for _, format := range []string{"json", "yaml", "toml"} {
		_, out, _ := runCLI(t, f.env, "--format", format, "--sni", "ok.test", srv.Addr)
		rep := decode(t, format, out)
		revs := rep.Results[0].Chain[0].Revocation
		if len(revs) != 1 || revs[0].Status != "good" || revs[0].Source != "staple" {
			t.Errorf("%s: leaf revocation = %+v", format, revs)
		}
	}
}

func TestStapleWithoutPresentedIssuerIsUnknown(t *testing.T) {
	f := newRevFixture(t, testutil.CertOpts{})
	f.interResp.Revoke(f.leaf)
	srv := testutil.StartTLSStapled(t, f.interResp.Staple(f.leaf), f.leaf)

	_, out, _ := runCLI(t, f.env, "--no-color", "--sni", "ok.test", srv.Addr)
	if !strings.Contains(out, "unknown (staple)") || strings.Contains(out, "revoked") {
		t.Errorf("unauthenticated staple must be unknown:\n%s", out)
	}
}

func TestStapleSignedByOrdinaryServerCertIsUnknown(t *testing.T) {
	f := newRevFixture(t, testutil.CertOpts{})
	other := f.inter.Issue(t, testutil.CertOpts{CommonName: "other.test", DNSNames: []string{"other.test"}})
	f.interResp.SignWith(other)
	srv := testutil.StartTLSStapled(t, f.interResp.Staple(f.leaf), f.leaf, &f.inter.Cert)

	_, out, _ := runCLI(t, f.env, "--no-color", "--sni", "ok.test", srv.Addr)
	if !strings.Contains(out, "unknown (staple)") || strings.Contains(out, "good (staple)") {
		t.Errorf("response signed by a server certificate must be unknown:\n%s", out)
	}
}

func TestStapleSignedByDelegatedResponderIsAccepted(t *testing.T) {
	f := newRevFixture(t, testutil.CertOpts{})
	del := f.inter.Issue(t, testutil.CertOpts{CommonName: "responder", ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}})
	f.interResp.SignWith(del)
	srv := testutil.StartTLSStapled(t, f.interResp.Staple(f.leaf), f.leaf, &f.inter.Cert)

	_, out, _ := runCLI(t, f.env, "--no-color", "--sni", "ok.test", srv.Addr)
	if !strings.Contains(out, "good (staple)") {
		t.Errorf("delegated responder should be accepted:\n%s", out)
	}
}

func TestStapleFreshnessBounds(t *testing.T) {
	for name, tc := range map[string]struct {
		age    time.Duration
		noNext bool
	}{
		"future issue time":            {-time.Hour, false},
		"over-age without next-update": {30 * 24 * time.Hour, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRevFixture(t, testutil.CertOpts{})
			f.interResp.IssuedAgo(tc.age, tc.noNext)
			srv := testutil.StartTLSStapled(t, f.interResp.Staple(f.leaf), f.leaf, &f.inter.Cert)

			_, out, _ := runCLI(t, f.env, "--no-color", "--sni", "ok.test", srv.Addr)
			if !strings.Contains(out, "unknown (staple)") {
				t.Errorf("expected unknown:\n%s", out)
			}
		})
	}
}

func TestStapleRecentWithoutNextUpdateIsGood(t *testing.T) {
	f := newRevFixture(t, testutil.CertOpts{})
	f.interResp.IssuedAgo(time.Hour, true)
	srv := testutil.StartTLSStapled(t, f.interResp.Staple(f.leaf), f.leaf, &f.inter.Cert)

	_, out, _ := runCLI(t, f.env, "--no-color", "--sni", "ok.test", srv.Addr)
	if !strings.Contains(out, "good (staple)") {
		t.Errorf("expected good:\n%s", out)
	}
}

func TestLiveRevocationResolvesIssuerFromTrustStoreAndAnyOrder(t *testing.T) {
	for name, order := range map[string]func(f *revFixture) []*testutil.Cert{
		"leaf and intermediate": func(f *revFixture) []*testutil.Cert { return []*testutil.Cert{&f.inter.Cert} },
		"out of order":          func(f *revFixture) []*testutil.Cert { return []*testutil.Cert{&f.root.Cert, &f.inter.Cert} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRevFixture(t, testutil.CertOpts{})
			srv := testutil.StartTLS(t, f.leaf, order(f)...)

			_, out, _ := runCLI(t, f.env, "--no-color", "--revocation", "--sni", "ok.test", srv.Addr)
			if strings.Contains(out, "unknown (") {
				t.Errorf("spurious unknown:\n%s", out)
			}
			if got := strings.Count(out, "good (ocsp)"); got != 2 {
				t.Errorf("good (ocsp) count = %d, want 2:\n%s", got, out)
			}
		})
	}
}

func TestNoRevocationURLIsNotLabelledCRL(t *testing.T) {
	f := newRevFixture(t, testutil.CertOpts{})
	f.leaf = f.inter.Issue(t, testutil.CertOpts{CommonName: "ok.test", DNSNames: []string{"ok.test"}})
	srv := testutil.StartTLS(t, f.leaf, &f.inter.Cert)

	_, out, _ := runCLI(t, f.env, "--no-color", "--revocation", "--sni", "ok.test", srv.Addr)
	if strings.Contains(out, "(crl)") {
		t.Errorf("source mislabelled as CRL:\n%s", out)
	}
}
