package main

import (
	"strings"
	"testing"

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
