package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/sollie/sslcheck/internal/render"
	"github.com/sollie/sslcheck/internal/testutil"
	"gopkg.in/yaml.v3"
)

func decode(t *testing.T, format, out string) render.Report {
	t.Helper()
	var r render.Report
	var err error
	switch format {
	case "json":
		err = json.Unmarshal([]byte(out), &r)
	case "yaml":
		err = yaml.Unmarshal([]byte(out), &r)
	case "toml":
		err = toml.Unmarshal([]byte(out), &r)
	}
	if err != nil {
		t.Fatalf("%s does not parse: %v\n%s", format, err, out)
	}
	return r
}

func TestStructuredFormatsParseBackToSameData(t *testing.T) {
	root := testutil.NewCA(t, "Test Root")
	leaf := root.Issue(t, testutil.CertOpts{CommonName: "leaf.test", DNSNames: []string{"leaf.test", "alt.test"}})
	srv := testutil.StartTLS(t, leaf, &root.Cert)
	dead := testutil.StartTLS(t, leaf)
	deadAddr := dead.Addr
	dead.Close()

	var reports []render.Report
	for _, f := range []string{"json", "yaml", "toml"} {
		code, out, errs := runCLI(t, nil, "-f", f, "--timeout", "2s", srv.Addr, deadAddr)
		if code != 1 {
			t.Fatalf("%s: exit %d, stderr: %s", f, code, errs)
		}
		reports = append(reports, decode(t, f, out))
	}
	first := reports[0]
	if first.SchemaVersion != 1 || len(first.Results) != 2 {
		t.Fatalf("unexpected report: %+v", first)
	}
	if r := first.Results[0]; r.Target != srv.Addr || r.TLSVersion == "" || len(r.Chain) != 2 ||
		!strings.HasPrefix(r.Chain[0].Subject, "CN=leaf.test") || len(r.Chain[0].SANs) != 2 || r.Chain[0].PEM != "" {
		t.Errorf("unexpected result: %+v", r)
	}
	if first.Results[1].Error == "" || len(first.Results[1].Chain) != 0 {
		t.Errorf("error result not reported: %+v", first.Results[1])
	}
	for i, r := range reports[1:] {
		if !reflect.DeepEqual(first, r) {
			t.Errorf("format %d differs from json:\n%+v\n%+v", i+1, first, r)
		}
	}
}

func TestSingleTargetStillYieldsResultsArray(t *testing.T) {
	srv := testutil.StartTLS(t, testutil.SelfSigned(t, testutil.CertOpts{CommonName: "one.test"}))
	_, out, _ := runCLI(t, nil, "--format", "json", srv.Addr)
	var raw map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["schema_version"]; !ok {
		t.Error("schema_version missing")
	}
	if res, ok := raw["results"].([]any); !ok || len(res) != 1 {
		t.Errorf("results = %v, want one-element array", raw["results"])
	}
}

func TestPEMFlag(t *testing.T) {
	srv := testutil.StartTLS(t, testutil.SelfSigned(t, testutil.CertOpts{CommonName: "pem.test"}))
	for _, f := range []string{"json", "yaml", "toml"} {
		_, out, _ := runCLI(t, nil, "-f", f, "--pem", srv.Addr)
		r := decode(t, f, out)
		if p := r.Results[0].Chain[0].PEM; !strings.HasPrefix(p, "-----BEGIN CERTIFICATE-----") {
			t.Errorf("%s: pem = %q", f, p)
		}
	}

	_, out, _ := runCLI(t, nil, "--no-color", "--pem", srv.Addr)
	if strings.Count(out, "-----BEGIN CERTIFICATE-----") != 1 {
		t.Errorf("pretty output should contain one PEM block:\n%s", out)
	}
	_, out, _ = runCLI(t, nil, "--no-color", srv.Addr)
	if strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Errorf("PEM printed without --pem:\n%s", out)
	}
}

func TestUnknownFormatExitsOne(t *testing.T) {
	if code, _, errs := runCLI(t, nil, "-f", "xml", "x.test"); code != 1 || errs == "" {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
}

func TestColourRules(t *testing.T) {
	srv := testutil.StartTLS(t, testutil.SelfSigned(t, testutil.CertOpts{CommonName: "c.test"}))
	const esc = "\x1b["
	cases := []struct {
		name   string
		env    map[string]string
		args   []string
		colour bool
	}{
		{"non-TTY", nil, nil, false},
		{"forced on", map[string]string{"CLICOLOR_FORCE": "1"}, nil, true},
		{"NO_COLOR beats force", map[string]string{"CLICOLOR_FORCE": "1", "NO_COLOR": "1"}, nil, false},
		{"--no-color beats force", map[string]string{"CLICOLOR_FORCE": "1"}, []string{"--no-color"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, out, _ := runCLI(t, c.env, append(c.args, srv.Addr)...)
			if got := strings.Contains(out, esc); got != c.colour {
				t.Errorf("colour = %v, want %v:\n%q", got, c.colour, out)
			}
		})
	}
	_, out, _ := runCLI(t, map[string]string{"CLICOLOR_FORCE": "1"}, "-f", "json", srv.Addr)
	if strings.Contains(out, esc) {
		t.Error("structured output must never be coloured")
	}
}
