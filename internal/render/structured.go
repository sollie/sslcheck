package render

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/sollie/sslcheck/internal/scan"
	"go.yaml.in/yaml/v3"
)

// SchemaVersion is bumped on incompatible changes to the structured output.
const SchemaVersion = 1

// Report is the document written for json, yaml and toml output. Each field
// carries the same name in all three encodings; add new fields here with all
// three tags and omitempty where absent values are meaningful.
type Report struct {
	SchemaVersion int      `json:"schema_version" yaml:"schema_version" toml:"schema_version"`
	Results       []Result `json:"results" yaml:"results" toml:"results"`
}

// Result is one Target's Scan.
type Result struct {
	Target     string        `json:"target" yaml:"target" toml:"target"`
	SNI        string        `json:"sni,omitempty" yaml:"sni,omitempty" toml:"sni,omitempty"`
	TLSVersion string        `json:"tls_version,omitempty" yaml:"tls_version,omitempty" toml:"tls_version,omitempty"`
	Error      string        `json:"error,omitempty" yaml:"error,omitempty" toml:"error,omitempty"`
	Chain      []Certificate `json:"chain,omitempty" yaml:"chain,omitempty" toml:"chain,omitempty"`
	// SCTs lists every SCT found, with its verification outcome.
	SCTs []SCT `json:"scts,omitempty" yaml:"scts,omitempty" toml:"scts,omitempty"`
	// Verdicts holds one Verdict per Trust store; absent when the scan failed.
	Verdicts []Verdict `json:"verdicts,omitempty" yaml:"verdicts,omitempty" toml:"verdicts,omitempty"`
	// SCTCount is the number of SCTs found and SCTValid the number of distinct logs with a valid one.
	// Both are absent when the Scan failed, so a failure is not read as zero SCTs.
	SCTCount   *int   `json:"sct_count,omitempty" yaml:"sct_count,omitempty" toml:"sct_count,omitempty"`
	SCTValid   *int   `json:"sct_valid,omitempty" yaml:"sct_valid,omitempty" toml:"sct_valid,omitempty"`
	SCTLogList string `json:"sct_log_list,omitempty" yaml:"sct_log_list,omitempty" toml:"sct_log_list,omitempty"`
}

// Verdict is the outcome of verifying the chain against one Trust store.
type Verdict struct {
	Store     string `json:"store" yaml:"store" toml:"store"`
	StoreInfo string `json:"store_info" yaml:"store_info" toml:"store_info"`
	// Name is the hostname the chain was matched against: the SNI name or Target host.
	Name          string    `json:"name,omitempty" yaml:"name,omitempty" toml:"name,omitempty"`
	Pass          bool      `json:"pass" yaml:"pass" toml:"pass"`
	Unavailable   bool      `json:"unavailable" yaml:"unavailable" toml:"unavailable"`
	Reasons       []string  `json:"reasons,omitempty" yaml:"reasons,omitempty" toml:"reasons,omitempty"`
	Path          []string  `json:"path,omitempty" yaml:"path,omitempty" toml:"path,omitempty"`
	Anchor        string    `json:"anchor,omitempty" yaml:"anchor,omitempty" toml:"anchor,omitempty"`
	HostnameMatch bool      `json:"hostname_match" yaml:"hostname_match" toml:"hostname_match"`
	Findings      []Finding `json:"findings,omitempty" yaml:"findings,omitempty" toml:"findings,omitempty"`
}

// Finding is a problem or notice raised in a Verdict.
type Finding struct {
	Severity string `json:"severity" yaml:"severity" toml:"severity"`
	Message  string `json:"message" yaml:"message" toml:"message"`
}

// SCT is one signed certificate timestamp.
type SCT struct {
	Source    string `json:"source" yaml:"source" toml:"source"`
	LogID     string `json:"log_id" yaml:"log_id" toml:"log_id"`
	Log       string `json:"log,omitempty" yaml:"log,omitempty" toml:"log,omitempty"`
	Timestamp string `json:"timestamp,omitempty" yaml:"timestamp,omitempty" toml:"timestamp,omitempty"`
	Valid     bool   `json:"valid" yaml:"valid" toml:"valid"`
	Detail    string `json:"detail,omitempty" yaml:"detail,omitempty" toml:"detail,omitempty"`
}

// Certificate is one certificate of the Presented chain.
type Certificate struct {
	Subject       string   `json:"subject" yaml:"subject" toml:"subject"`
	SANs          []string `json:"sans,omitempty" yaml:"sans,omitempty" toml:"sans,omitempty"`
	Issuer        string   `json:"issuer" yaml:"issuer" toml:"issuer"`
	Serial        string   `json:"serial" yaml:"serial" toml:"serial"`
	NotBefore     string   `json:"not_before" yaml:"not_before" toml:"not_before"`
	NotAfter      string   `json:"not_after" yaml:"not_after" toml:"not_after"`
	DaysRemaining int      `json:"days_remaining" yaml:"days_remaining" toml:"days_remaining"`
	SigAlgorithm  string   `json:"signature_algorithm" yaml:"signature_algorithm" toml:"signature_algorithm"`
	KeyType       string   `json:"key_type" yaml:"key_type" toml:"key_type"`
	KeyBits       int      `json:"key_bits" yaml:"key_bits" toml:"key_bits"`
	SHA256        string   `json:"sha256_fingerprint" yaml:"sha256_fingerprint" toml:"sha256_fingerprint"`
	PEM           string   `json:"pem,omitempty" yaml:"pem,omitempty" toml:"pem,omitempty"`
	// Revocation lists the Revocation status results for this certificate.
	Revocation []Revocation `json:"revocation,omitempty" yaml:"revocation,omitempty" toml:"revocation,omitempty"`
}

// Revocation is the Revocation status of a certificate from one source.
type Revocation struct {
	Status string `json:"status" yaml:"status" toml:"status"`
	Source string `json:"source" yaml:"source" toml:"source"`
	Detail string `json:"detail,omitempty" yaml:"detail,omitempty" toml:"detail,omitempty"`
}

// NewReport converts scan results into the structured model. PEM is only
// included when withPEM is set.
func NewReport(results []scan.Result, withPEM bool) Report {
	rep := Report{SchemaVersion: SchemaVersion, Results: make([]Result, 0, len(results))}
	for _, r := range results {
		out := Result{Target: r.Target.Address(), SNI: r.Target.SNI, TLSVersion: r.TLSVersion}
		if r.Err != nil {
			out.Error = r.Err.Error()
		}
		for _, c := range r.Chain {
			cert := Certificate{
				Subject:       c.Subject,
				SANs:          c.SANs,
				Issuer:        c.Issuer,
				Serial:        c.Serial,
				NotBefore:     c.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:      c.NotAfter.UTC().Format(time.RFC3339),
				DaysRemaining: c.DaysRemaining,
				SigAlgorithm:  c.SigAlgorithm,
				KeyType:       c.KeyType,
				KeyBits:       c.KeyBits,
				SHA256:        c.SHA256,
			}
			if withPEM {
				cert.PEM = c.PEM
			}
			for _, rv := range c.Revocation {
				cert.Revocation = append(cert.Revocation, Revocation{Status: string(rv.Status), Source: string(rv.Source), Detail: rv.Detail})
			}
			out.Chain = append(out.Chain, cert)
		}
		if r.CT != nil && r.Err == nil {
			count, valid := len(r.CT.SCTs), r.CT.Valid
			out.SCTCount, out.SCTValid, out.SCTLogList = &count, &valid, r.CT.LogList
			for _, s := range r.CT.SCTs {
				ts := ""
				if !s.Timestamp.IsZero() {
					ts = s.Timestamp.UTC().Format(time.RFC3339)
				}
				out.SCTs = append(out.SCTs, SCT{Source: s.Source, LogID: s.LogID, Log: s.Log, Timestamp: ts, Valid: s.Valid, Detail: s.Detail})
			}
		}
		for _, v := range r.Verdicts {
			vo := Verdict{Store: v.Store, StoreInfo: v.StoreInfo, Name: v.Name, Pass: v.Pass, Unavailable: v.Unavailable,
				Reasons: v.Reasons, Path: v.Path, Anchor: v.Anchor, HostnameMatch: v.HostnameMatch}
			for _, f := range v.Findings {
				vo.Findings = append(vo.Findings, Finding{Severity: string(f.Severity), Message: f.Message})
			}
			out.Verdicts = append(out.Verdicts, vo)
		}
		rep.Results = append(rep.Results, out)
	}
	return rep
}

// Formats lists the accepted values of --format.
var Formats = []string{"pretty", "json", "yaml", "toml"}

// Structured writes rep in the given structured format (json, yaml or toml).
func Structured(w io.Writer, rep Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "yaml":
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		if err := enc.Encode(rep); err != nil {
			return err
		}
		return enc.Close()
	case "toml":
		return toml.NewEncoder(w).Encode(rep)
	}
	return fmt.Errorf("unknown format %q", format)
}
