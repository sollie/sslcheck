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

type palette struct {
	heading, target, label, value, dim, ok, warn, bad *color.Color
}

// ColorLevel is how much colour the output terminal supports.
type ColorLevel int

const (
	ColorNone ColorLevel = iota
	// Color16 uses the bright ANSI colours every colour terminal has.
	Color16
	// ColorTrue uses 24-bit colour.
	ColorTrue
)

func newPalette(level ColorLevel) palette {
	set := func(c *color.Color) *color.Color {
		if level == ColorNone {
			c.DisableColor()
		} else {
			c.EnableColor()
		}
		return c
	}
	// pick returns the 24-bit colour when supported, else the ANSI fallback.
	pick := func(r, g, b int, fallback color.Attribute, attrs ...color.Attribute) *color.Color {
		if level == ColorTrue {
			return set(color.RGB(r, g, b).Add(attrs...))
		}
		return set(color.New(append([]color.Attribute{fallback}, attrs...)...))
	}
	return palette{
		heading: pick(34, 211, 238, color.FgHiCyan, color.Bold),
		target:  pick(232, 121, 249, color.FgHiMagenta, color.Bold),
		label:   pick(96, 165, 250, color.FgHiBlue, color.Bold),
		value:   pick(248, 250, 252, color.FgHiWhite, color.Bold),
		dim:     set(color.New(color.Faint)),
		ok:      pick(74, 222, 128, color.FgHiGreen),
		warn:    pick(251, 191, 36, color.FgHiYellow),
		bad:     pick(248, 113, 113, color.FgHiRed),
	}
}

// Pretty writes a report for each result in the given order.
func Pretty(w io.Writer, results []scan.Result, level ColorLevel) {
	PrettyPEM(w, results, level, false)
}

// PrettyPEM is Pretty, optionally followed by a PEM block per certificate.
func PrettyPEM(w io.Writer, results []scan.Result, level ColorLevel, withPEM bool) {
	p := newPalette(level)
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
			field("Expiry", expiry(p, c))
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

func expiry(p palette, c scan.Certificate) string {
	days := c.DaysRemaining
	switch {
	case c.Expired && days >= 0:
		return p.bad.Sprint("expired less than a day ago")
	case c.Expired:
		return p.bad.Sprintf("expired %d days ago", -days)
	case c.ExpiresSoon:
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
