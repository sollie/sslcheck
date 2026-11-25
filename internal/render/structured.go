package render

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/sollie/sslcheck/internal/scan"
	"gopkg.in/yaml.v3"
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
	SHA256        string   `json:"sha256" yaml:"sha256" toml:"sha256"`
	PEM           string   `json:"pem,omitempty" yaml:"pem,omitempty" toml:"pem,omitempty"`
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
			out.Chain = append(out.Chain, cert)
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
