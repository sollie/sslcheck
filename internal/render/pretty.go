// Package render prints scan results as colourised pretty text.
package render

import (
	"fmt"
	"github.com/sollie/sslcheck/internal/revocation"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/sollie/sslcheck/internal/scan"
)

// expiryWarnDays is the threshold below which a certificate gets a warning.
const expiryWarnDays = 30

type palette struct {
	heading, label, ok, warn, bad *color.Color
}

func newPalette(useColor bool) palette {
	mk := func(a ...color.Attribute) *color.Color {
		c := color.New(a...)
		if useColor {
			c.EnableColor()
		} else {
			c.DisableColor()
		}
		return c
	}
	return palette{
		heading: mk(color.Bold, color.FgCyan),
		label:   mk(color.Bold),
		ok:      mk(color.FgGreen),
		warn:    mk(color.FgYellow),
		bad:     mk(color.FgRed),
	}
}

// Pretty writes a report for each result in the given order.
func Pretty(w io.Writer, results []scan.Result, useColor bool) {
	PrettyPEM(w, results, useColor, false)
}

// PrettyPEM is Pretty, optionally followed by a PEM block per certificate.
func PrettyPEM(w io.Writer, results []scan.Result, useColor, withPEM bool) {
	p := newPalette(useColor)
	for i, r := range results {
		if i > 0 {
			_, _ = fmt.Fprintln(w)
		}
		_, _ = fmt.Fprintf(w, "%s\n", p.heading.Sprintf("Target %s", r.Target.Address()))
		if r.Err != nil {
			_, _ = fmt.Fprintf(w, "  %s %v\n", p.bad.Sprint("Error:"), r.Err)
			continue
		}
		_, _ = fmt.Fprintf(w, "  %s %s\n", p.label.Sprint("TLS version:"), r.TLSVersion)
		for n, c := range r.Chain {
			_, _ = fmt.Fprintf(w, "\n%s\n", p.heading.Sprintf("Certificate %d of %d", n+1, len(r.Chain)))
			field := func(name, val string) {
				_, _ = fmt.Fprintf(w, "  %s %s\n", p.label.Sprintf("%-14s", name+":"), val)
			}
			field("Subject", c.Subject)
			if len(c.SANs) > 0 {
				field("SANs", strings.Join(c.SANs, ", "))
			}
			field("Issuer", c.Issuer)
			field("Serial", c.Serial)
			field("Not Before", c.NotBefore.UTC().Format("2006-01-02 15:04:05 MST"))
			field("Not After", c.NotAfter.UTC().Format("2006-01-02 15:04:05 MST"))
			field("Expiry", expiry(p, c.DaysRemaining))
			field("Signature", c.SigAlgorithm)
			field("Key", fmt.Sprintf("%s %d bits", c.KeyType, c.KeyBits))
			field("SHA-256", c.SHA256)
			for _, rv := range r.Revocation {
				if rv.Cert == n {
					field("Revocation", revocationText(p, rv))
				}
			}
			if withPEM {
				_, _ = fmt.Fprintf(w, "\n%s", c.PEM)
			}
		}
		writeVerdicts(w, p, r.Verdicts)
	}
}

func expiry(p palette, days int) string {
	switch {
	case days < 0:
		return p.bad.Sprintf("expired %d days ago", -days)
	case days < expiryWarnDays:
		return p.warn.Sprintf("%d days remaining (warning)", days)
	}
	return p.ok.Sprintf("%d days remaining", days)
}

func revocationText(p palette, rv revocation.Result) string {
	text := fmt.Sprintf("%s (%s)", rv.Status, rv.Source)
	switch rv.Status {
	case revocation.Good:
		return p.ok.Sprint(text)
	case revocation.Revoked:
		return p.bad.Sprint(text)
	}
	return p.warn.Sprint(text)
}
