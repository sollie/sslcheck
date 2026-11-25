// Package render prints scan results as colourised pretty text.
package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/sollie/sslcheck/internal/ct"
	"github.com/sollie/sslcheck/internal/revocation"
	"github.com/sollie/sslcheck/internal/scan"
)

// expiryWarnDays is the threshold below which a certificate gets a warning.
const expiryWarnDays = 30

type palette struct {
	heading, target, label, value, dim, ok, warn, bad *color.Color
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
		heading: mk(color.Bold, color.FgHiCyan),
		target:  mk(color.Bold, color.FgHiMagenta),
		label:   mk(color.Bold, color.FgHiBlue),
		value:   mk(color.Bold, color.FgHiWhite),
		dim:     mk(color.Faint),
		ok:      mk(color.FgHiGreen),
		warn:    mk(color.FgHiYellow),
		bad:     mk(color.FgHiRed),
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
		_, _ = fmt.Fprintf(w, "%s\n", p.target.Sprintf("Target %s", r.Target.Address()))
		if r.Err != nil {
			_, _ = fmt.Fprintf(w, "  %s %v\n", p.bad.Sprint("Error:"), r.Err)
			continue
		}
		_, _ = fmt.Fprintf(w, "  %s %s\n", p.label.Sprint("TLS version:"), tlsVersion(p, r.TLSVersion))
		for n, c := range r.Chain {
			_, _ = fmt.Fprintf(w, "\n%s\n", p.heading.Sprintf("Certificate %d of %d", n+1, len(r.Chain)))
			field := func(name, val string) {
				_, _ = fmt.Fprintf(w, "  %s %s\n", p.label.Sprintf("%-14s", name+":"), val)
			}
			field("Subject", p.value.Sprint(c.Subject))
			if len(c.SANs) > 0 {
				field("SANs", strings.Join(c.SANs, ", "))
			}
			field("Issuer", c.Issuer)
			field("Serial", p.dim.Sprint(c.Serial))
			field("Not Before", c.NotBefore.UTC().Format("2006-01-02 15:04:05 MST"))
			field("Not After", c.NotAfter.UTC().Format("2006-01-02 15:04:05 MST"))
			field("Expiry", expiry(p, c.DaysRemaining))
			field("Signature", c.SigAlgorithm)
			field("Key", fmt.Sprintf("%s %d bits", c.KeyType, c.KeyBits))
			field("SHA-256", p.dim.Sprint(c.SHA256))
			for _, rv := range c.Revocation {
				field("Revocation", revocationText(p, rv))
			}
			if withPEM {
				_, _ = fmt.Fprintf(w, "\n%s", c.PEM)
			}
		}
		writeCT(w, p, r.CT)
		writeVerdicts(w, p, r.Verdicts)
	}
}

// tlsVersion flags protocol versions older than TLS 1.2.
func tlsVersion(p palette, v string) string {
	switch v {
	case "TLS 1.3", "TLS 1.2":
		return p.ok.Sprint(v)
	}
	return p.warn.Sprint(v)
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

func writeCT(w io.Writer, p palette, res *ct.Result) {
	if res == nil {
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s\n", p.heading.Sprint("Certificate Transparency"))
	count := fmt.Sprintf("%d SCTs, %d valid (log list: %s)", len(res.SCTs), res.Valid, res.LogList)
	if res.Valid < ct.MinSCTs {
		count = p.warn.Sprint(count)
	}
	_, _ = fmt.Fprintf(w, "  %s %s\n", p.label.Sprint("SCTs:"), count)
	for _, s := range res.SCTs {
		status := p.ok.Sprint("valid")
		if !s.Valid {
			status = p.warn.Sprintf("invalid: %s", s.Detail)
		}
		name := s.Log
		if name == "" {
			name = "unknown log"
		}
		_, _ = fmt.Fprintf(w, "    %s  %s (%s)  %s  %s\n", s.Timestamp.Format("2006-01-02 15:04:05 MST"), s.LogID, name, s.Source, status)
	}
}
