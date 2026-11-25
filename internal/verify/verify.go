// Package verify checks a Presented chain against Trust stores, producing one
// Verdict per store (see ADR-0002).
package verify

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/sollie/sslcheck/internal/ct"
	"github.com/sollie/sslcheck/internal/revocation"
	"github.com/sollie/sslcheck/internal/truststore"
)

// ExpiryWarnDays is how close to expiry the leaf must be to raise a warning.
const ExpiryWarnDays = 30

// Reasons a Verdict can fail.
const (
	ReasonExpired          = "expired"
	ReasonNotYetValid      = "not yet valid"
	ReasonUnknownAuthority = "unknown authority"
	ReasonHostnameMismatch = "hostname mismatch"
	ReasonRevoked          = "revoked"
)

// Severity of a Finding.
type Severity string

// Finding severities.
const (
	Failure Severity = "failure"
	Warning Severity = "warning"
)

// Finding is a single problem or notice raised in a Verdict.
type Finding struct {
	Severity Severity
	Message  string
}

// Verdict is the result of verifying a Presented chain against one Trust store.
type Verdict struct {
	Store string
	// StoreInfo is the source and date of the Trust store.
	StoreInfo string
	Pass      bool
	// Unavailable reports that the store holds no roots, so no verdict could be
	// reached; it is neither a pass nor a failure.
	Unavailable bool
	// Reasons lists the failure reasons; empty when Pass.
	Reasons []string
	// Path is the verified path as subject strings, leaf first, ending at the anchor.
	Path []string
	// Anchor is the subject of the trust anchor, empty when none was found.
	Anchor string
	// HostnameMatch reports whether the leaf matches the checked name.
	HostnameMatch bool
	Name          string // the hostname checked: SNI name or Target host
	Findings      []Finding
}

// Verify verifies chain (leaf first, as presented) for name against each store at time now.
func Verify(chain []*x509.Certificate, name string, stores []truststore.Store, now time.Time) []Verdict {
	out := make([]Verdict, 0, len(stores))
	for _, s := range stores {
		out = append(out, verifyOne(chain, name, s, now))
	}
	return out
}

func verifyOne(chain []*x509.Certificate, name string, store truststore.Store, now time.Time) Verdict {
	v := Verdict{Store: store.Name, StoreInfo: store.Description(), Name: name}
	if store.Unavailable {
		v.Unavailable = true
		return v
	}
	if len(chain) == 0 {
		v.Reasons = []string{ReasonUnknownAuthority}
		v.Findings = []Finding{{Failure, "no certificates presented"}}
		return v
	}
	leaf := chain[0]
	v.HostnameMatch = leaf.VerifyHostname(name) == nil

	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         store.Roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	paths, err := leaf.Verify(opts)
	if err != nil {
		var invalid x509.CertificateInvalidError
		var unknown x509.UnknownAuthorityError
		switch {
		case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
			reason := ReasonExpired
			if now.Before(leaf.NotBefore) {
				reason = ReasonNotYetValid
			}
			v.Reasons = append(v.Reasons, reason)
			v.Findings = append(v.Findings, Finding{Failure, fmt.Sprintf("%s: %s", reason, invalid.Detail)})
			// Re-verify inside the leaf's validity to still report path and anchor.
			opts.CurrentTime = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
			paths, _ = leaf.Verify(opts)
		case errors.As(err, &unknown):
			v.Reasons = append(v.Reasons, ReasonUnknownAuthority)
			v.Findings = append(v.Findings, Finding{Failure, "chain does not lead to a trusted root in the " + store.Name + " store"})
		default:
			v.Reasons = append(v.Reasons, err.Error())
			v.Findings = append(v.Findings, Finding{Failure, err.Error()})
		}
	}
	if len(paths) > 0 {
		for _, c := range paths[0] {
			v.Path = append(v.Path, c.Subject.String())
		}
		v.Anchor = paths[0][len(paths[0])-1].Subject.String()
	}
	if !v.HostnameMatch {
		v.Reasons = append(v.Reasons, ReasonHostnameMismatch)
		v.Findings = append(v.Findings, Finding{Failure, fmt.Sprintf("certificate does not match %q", name)})
	}
	v.Pass = len(v.Reasons) == 0
	if days := int(leaf.NotAfter.Sub(now).Hours() / 24); !now.After(leaf.NotAfter) && days <= ExpiryWarnDays {
		v.Findings = append(v.Findings, Finding{Warning, fmt.Sprintf("leaf certificate expires in %d days", days)})
	}
	return v
}

// ApplyCT adds a warning to every verdict when the SCTs found are missing,
// too few or invalid. It never fails a Verdict.
func ApplyCT(verdicts []Verdict, res ct.Result) {
	var msgs []string
	for _, s := range res.SCTs {
		if !s.Valid {
			msgs = append(msgs, fmt.Sprintf("SCT from %s (log %s) is not valid: %s", s.Source, s.LogID, s.Detail))
		}
	}
	switch {
	case len(res.SCTs) == 0:
		msgs = append(msgs, "no SCTs presented (Certificate Transparency)")
	case res.Valid < ct.MinSCTs:
		msgs = append(msgs, fmt.Sprintf("only %d valid SCT(s) from distinct logs, expected at least %d", res.Valid, ct.MinSCTs))
	}
	for i := range verdicts {
		for _, m := range msgs {
			verdicts[i].Findings = append(verdicts[i].Findings, Finding{Warning, m})
		}
	}
}

// ApplyRevocation folds Revocation status results into verdicts: a revoked
// certificate fails the Verdict, an unknown status only adds a warning.
func ApplyRevocation(verdicts []Verdict, results []revocation.Result) {
	for i := range verdicts {
		v := &verdicts[i]
		for _, r := range results {
			switch r.Status {
			case revocation.Revoked:
				if !slices.Contains(v.Reasons, ReasonRevoked) {
					v.Reasons = append(v.Reasons, ReasonRevoked)
				}
				v.Findings = append(v.Findings, Finding{Failure, fmt.Sprintf("certificate %d is revoked (%s): %s", r.Cert, r.Source, r.Detail)})
			case revocation.Unknown:
				v.Findings = append(v.Findings, Finding{Warning, fmt.Sprintf("revocation status of certificate %d is unknown (%s): %s", r.Cert, r.Source, r.Detail)})
			}
		}
		v.Pass = len(v.Reasons) == 0
	}
}
