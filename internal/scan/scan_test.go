package scan

import (
	"context"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/sollie/sslcheck/internal/testutil"
	"github.com/sollie/sslcheck/internal/truststore"
	"github.com/sollie/sslcheck/internal/verify"
)

func storeOf(t *testing.T, ca *testutil.CA) truststore.Store {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.PEM()) {
		t.Fatal("bad root PEM")
	}
	return truststore.Store{Name: "Test", Roots: pool, Source: "test"}
}

func serverTarget(s *testutil.Server) Target { return Target{Host: s.Host, Port: s.Port} }

func TestScanAllKeepsInputOrderAndJudgesEachTarget(t *testing.T) {
	ca := testutil.NewCA(t, "Test Root")
	opts := testutil.CertOpts{CommonName: "127.0.0.1", IPs: []net.IP{net.ParseIP("127.0.0.1")}}
	good := testutil.StartTLS(t, ca.Issue(t, opts))
	expired := testutil.StartTLS(t, ca.Issue(t, testutil.Expired(opts)))
	var targets []Target
	for range 4 {
		targets = append(targets, serverTarget(good), serverTarget(expired))
	}
	targets = append(targets, Target{Host: "127.0.0.1", Port: 1})

	results := ScanAll(context.Background(), targets, Options{Stores: []truststore.Store{storeOf(t, ca)}, Concurrency: 3, Timeout: 2 * time.Second})
	if len(results) != len(targets) {
		t.Fatalf("got %d results, want %d", len(results), len(targets))
	}
	for i, r := range results[:8] {
		if r.Target.Port != targets[i].Port {
			t.Fatalf("result %d is for port %d, want %d", i, r.Target.Port, targets[i].Port)
		}
		if r.Err != nil || len(r.Verdicts) != 1 {
			t.Fatalf("result %d: err=%v verdicts=%d", i, r.Err, len(r.Verdicts))
		}
		if wantFail := i%2 == 1; r.Failed() != wantFail {
			t.Errorf("result %d Failed() = %v, want %v", i, r.Failed(), wantFail)
		}
	}
	if last := results[8]; last.Err == nil || len(last.Verdicts) != 0 || last.Failed() {
		t.Errorf("unreachable Target: err=%v verdicts=%d failed=%v", last.Err, len(last.Verdicts), last.Failed())
	}
}

func TestScanAllUsesInjectedClock(t *testing.T) {
	ca := testutil.NewCA(t, "Test Root")
	srv := testutil.StartTLS(t, ca.Issue(t, testutil.CertOpts{CommonName: "127.0.0.1", IPs: []net.IP{net.ParseIP("127.0.0.1")}}))
	opts := Options{Stores: []truststore.Store{storeOf(t, ca)}, Timeout: 2 * time.Second}

	if r := ScanAll(context.Background(), []Target{serverTarget(srv)}, opts)[0]; r.Failed() {
		t.Fatalf("fresh certificate should pass: %+v", r.Verdicts)
	}
	opts.Now = func() time.Time { return time.Now().AddDate(10, 0, 0) }
	if r := ScanAll(context.Background(), []Target{serverTarget(srv)}, opts)[0]; !r.Failed() {
		t.Fatal("certificate should fail ten years from now")
	}
}

func TestFailedIgnoresUnavailableVerdicts(t *testing.T) {
	r := Result{Verdicts: []verify.Verdict{{Pass: true}, {Unavailable: true}}}
	if r.Failed() {
		t.Error("unavailable Verdict must not count as failed")
	}
	r.Verdicts = append(r.Verdicts, verify.Verdict{})
	if !r.Failed() {
		t.Error("failing Verdict must count")
	}
}
