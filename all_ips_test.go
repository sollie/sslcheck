package main

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/sollie/sslcheck/internal/testutil"
)

// requireLocalhostDual skips unless localhost resolves to both loopback families.
func requireLocalhostDual(t *testing.T) {
	t.Helper()
	ips, err := net.LookupIP("localhost")
	var v4, v6 bool
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = true
		} else if ip.Equal(net.IPv6loopback) {
			v6 = true
		}
	}
	if err != nil || !v4 || !v6 {
		t.Skip("localhost does not resolve to both 127.0.0.1 and ::1")
	}
}

func allIPsFixture(t *testing.T) (port string, v4Leaf, v6Leaf string) {
	t.Helper()
	requireLocalhostDual(t)
	root := testutil.NewCA(t, "Test Root")
	a := root.Issue(t, testutil.CertOpts{CommonName: "a.test", DNSNames: []string{"localhost"}})
	b := root.Issue(t, testutil.CertOpts{CommonName: "b.test", DNSNames: []string{"localhost"}})
	return strconv.Itoa(testutil.StartTLSDual(t, a, b)), a.Leaf.Subject.CommonName, b.Leaf.Subject.CommonName
}

func TestAllIPsScansEveryAddressV4First(t *testing.T) {
	port, _, _ := allIPsFixture(t)
	code, out, errs := runCLI(t, nil, "-f", "json", "--all-ips", "localhost:"+port)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	rep := decode(t, "json", out)
	if len(rep.Results) < 2 {
		t.Fatalf("want one Scan per address, got %d:\n%s", len(rep.Results), out)
	}
	first, last := rep.Results[0], rep.Results[len(rep.Results)-1]
	if first.Address != "127.0.0.1" || last.Address != "::1" {
		t.Errorf("addresses = %q ... %q, want 127.0.0.1 first and ::1 last", first.Address, last.Address)
	}
	for _, r := range rep.Results {
		if r.Target != "localhost:"+port || r.SNI != "localhost" {
			t.Errorf("target %q sni %q, want localhost:%s and SNI localhost", r.Target, r.SNI, port)
		}
	}
	if first.Chain[0].Subject == last.Chain[0].Subject {
		t.Errorf("each address should present its own chain, both gave %q", first.Chain[0].Subject)
	}
}

func TestAllIPsHonoursSNIOverride(t *testing.T) {
	port, _, _ := allIPsFixture(t)
	_, out, _ := runCLI(t, nil, "-f", "json", "--all-ips", "--sni", "alt.test", "localhost:"+port)
	for _, r := range decode(t, "json", out).Results {
		if r.SNI != "alt.test" {
			t.Errorf("SNI = %q for %s, want alt.test", r.SNI, r.Address)
		}
	}
}

func TestAllIPsFailsWhenOneAddressRefuses(t *testing.T) {
	requireLocalhostDual(t)
	root := testutil.NewCA(t, "Test Root")
	leaf := root.Issue(t, testutil.CertOpts{CommonName: "a.test", DNSNames: []string{"localhost"}})
	srv := testutil.StartTLS(t, leaf) // 127.0.0.1 only, so ::1 refuses
	code, out, _ := runCLI(t, nil, "-f", "json", "--all-ips", "localhost:"+strconv.Itoa(srv.Port))
	if code != 1 {
		t.Errorf("exit %d, want 1 when an address errors", code)
	}
	var ok, bad int
	for _, r := range decode(t, "json", out).Results {
		if r.Error != "" {
			bad++
		} else {
			ok++
		}
	}
	if ok == 0 || bad == 0 {
		t.Errorf("want a mix of successful and errored Scans, got %d ok, %d errored:\n%s", ok, bad, out)
	}
}

func TestAllIPsIgnoredForIPLiteral(t *testing.T) {
	root := testutil.NewCA(t, "Test Root")
	srv := testutil.StartTLS(t, root.Issue(t, testutil.CertOpts{CommonName: "a.test", DNSNames: []string{"a.test"}}))
	code, out, errs := runCLI(t, nil, "-f", "json", "--all-ips", srv.Addr)
	if code != 0 || !strings.Contains(errs, "--all-ips ignored") {
		t.Errorf("exit %d, stderr %q, want exit 0 and a note", code, errs)
	}
	rep := decode(t, "json", out)
	if len(rep.Results) != 1 || rep.Results[0].Address != "" {
		t.Errorf("IP literal should be scanned once without an address, got %+v", rep.Results)
	}
}
