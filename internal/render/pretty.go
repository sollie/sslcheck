// Package render prints scan results as colourised pretty text.
package render

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

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
func Pretty(w io.Writer, results []scan.Result, level ColorLevel) error {
	return PrettyPEM(w, results, level, false)
}

// errWriter remembers the first write error so rendering can report it once.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(b []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(b)
	e.err = err
	return n, err
}

// Safe escapes control and invisible characters in Target-derived text so they
// show as \xNN, \uNNNN or \UNNNNNNNN instead of acting on the terminal.
func Safe(s string) string {
	if !strings.ContainsFunc(s, unsafeRune) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == unicode.ReplacementChar:
			b.WriteString(`\ufffd`)
		case !unsafeRune(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	return r == unicode.ReplacementChar || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
}

func safeAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = Safe(s)
	}
	return out
}

// PrettyPEM is Pretty, optionally followed by a PEM block per certificate.
// It returns the first write error.
func PrettyPEM(out io.Writer, results []scan.Result, level ColorLevel, withPEM bool) error {
	w := &errWriter{w: out}
	p := newPalette(level)
	for i := 0; i < len(results); {
		n := addressRun(results[i:])
		if i > 0 {
			_, _ = fmt.Fprintln(w)
		}
		if n > 1 {
			writeAddressGroups(w, p, results[i:i+n], withPEM)
		} else {
			r := results[i]
			r.Target.IP = ""
			writeHeading(w, p, r.Target)
			writeBody(w, p, r, withPEM)
		}
		i += n
	}
	return w.err
}

func writeHeading(w io.Writer, p palette, t scan.Target) {
	_, _ = fmt.Fprintf(w, "%s\n", p.target.Sprintf("Target %s", Safe(t.Address())))
}

// addressRun is how many leading results are address Scans of one Target
// (under --all-ips); any other result counts as a run of one.
func addressRun(results []scan.Result) int {
	first := results[0]
	if first.Target.IP == "" {
		return 1
	}
	n := 1
	for n < len(results) && results[n].Target.IP != "" && results[n].TargetIndex == first.TargetIndex {
		n++
	}
	return n
}

// groupKey identifies what an address presented: the Presented chain, or the
// error that stopped the Scan.
type groupKey struct {
	err   string
	chain string
}

func keyOf(r scan.Result) groupKey {
	if r.Err != nil {
		return groupKey{err: r.Err.Error()}
	}
	var b strings.Builder
	for _, c := range r.Chain {
		b.WriteString(c.SHA256)
		b.WriteByte(',')
	}
	return groupKey{chain: b.String()}
}

// writeAddressGroups prints the Scans of one Target's addresses as Address
// groups: one full report per distinct Presented chain, then one per error.
func writeAddressGroups(w io.Writer, p palette, results []scan.Result, withPEM bool) {
	var order []groupKey
	groups := map[groupKey][]scan.Result{}
	for _, r := range results {
		k := keyOf(r)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	// Errored groups go last; the sort keeps first-seen order within each kind.
	sort.SliceStable(order, func(i, j int) bool {
		return groups[order[i]][0].Err == nil && groups[order[j]][0].Err != nil
	})
	t := results[0].Target
	writeHeading(w, p, t)
	_, _ = fmt.Fprintf(w, "  %s %d addresses, %d distinct\n", p.label.Sprint("Addresses:"), len(results), len(order))
	for n, k := range order {
		g := groups[k]
		_, _ = fmt.Fprintf(w, "\n%s\n", p.heading.Sprintf("Address group %d of %d: %s", n+1, len(order), Safe(addressList(g))))
		writeBody(w, p, g[0], withPEM)
		writeDiffs(w, p, g)
	}
}

// writeDiffs notes Evidence that differs between addresses sharing a Presented
// chain, so a node on an older protocol or without a staple still shows.
func writeDiffs(w io.Writer, p palette, g []scan.Result) {
	if g[0].Err != nil {
		return
	}
	fields := []struct {
		name string
		get  func(scan.Result) string
	}{
		{"TLS version", func(r scan.Result) string { return r.TLSVersion }},
		{"Cipher suite", func(r scan.Result) string { return r.CipherSuite }},
		{"OCSP staple", stapleSummary},
	}
	for _, f := range fields {
		var values []string
		byValue := map[string][]string{}
		for _, r := range g {
			v := f.get(r)
			if _, ok := byValue[v]; !ok {
				values = append(values, v)
			}
			byValue[v] = append(byValue[v], r.Target.IP)
		}
		if len(values) < 2 {
			continue
		}
		parts := make([]string, len(values))
		for i, v := range values {
			if v == "" {
				v = "none"
			}
			parts[i] = fmt.Sprintf("%s (%s)", v, strings.Join(byValue[values[i]], ", "))
		}
		_, _ = fmt.Fprintf(w, "\n  %s %s\n", p.warn.Sprintf("%s differs:", f.name), Safe(strings.Join(parts, "; ")))
	}
}

// stapleSummary lists the stapled OCSP result of each certificate in a Scan's chain.
func stapleSummary(r scan.Result) string {
	var parts []string
	for _, c := range r.Chain {
		for _, rv := range c.Revocation {
			if rv.Source != revocation.Staple {
				continue
			}
			parts = append(parts, string(rv.Status)+"/"+string(rv.Source))
		}
	}
	return strings.Join(parts, " ")
}

func addressList(g []scan.Result) string {
	ips := make([]string, len(g))
	for i, r := range g {
		ips[i] = r.Target.IP
	}
	return strings.Join(ips, ", ")
}

// writeBody prints a Scan's outcome below its heading.
func writeBody(w io.Writer, p palette, r scan.Result, withPEM bool) {
	if r.Err != nil {
		_, _ = fmt.Fprintf(w, "  %s %v\n", p.bad.Sprint("Error:"), Safe(r.Err.Error()))
		return
	}
	_, _ = fmt.Fprintf(w, "  %s %s\n", p.label.Sprint("TLS version:"), tlsVersion(p, r.TLSVersion))
	if r.CipherSuite != "" {
		cs := p.ok.Sprint(r.CipherSuite)
		if r.WeakCipher {
			cs = p.warn.Sprint(r.CipherSuite)
		}
		_, _ = fmt.Fprintf(w, "  %s %s\n", p.label.Sprint("Cipher suite:"), cs)
	}
	for n, c := range r.Chain {
		_, _ = fmt.Fprintf(w, "\n%s\n", p.heading.Sprintf("Certificate %d of %d", n+1, len(r.Chain)))
		field := func(name, val string) {
			_, _ = fmt.Fprintf(w, "  %s %s\n", p.label.Sprintf("%-14s", name+":"), val)
		}
		field("Subject", p.value.Sprint(Safe(c.Subject)))
		if len(c.SANs) > 0 {
			field("SANs", strings.Join(safeAll(c.SANs), ", "))
		}
		field("Issuer", Safe(c.Issuer))
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
	text := fmt.Sprintf("%s (%s)", Safe(string(rv.Status)), Safe(string(rv.Source)))
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
	count := fmt.Sprintf("%d SCTs, %d valid (log list: %s)", len(res.SCTs), res.Valid, Safe(res.LogList))
	if res.Valid < ct.MinSCTs {
		count = p.warn.Sprint(count)
	}
	_, _ = fmt.Fprintf(w, "  %s %s\n", p.label.Sprint("SCTs:"), count)
	for _, s := range res.SCTs {
		status := p.ok.Sprint("valid")
		if !s.Valid {
			status = p.warn.Sprintf("invalid: %s", Safe(s.Detail))
		}
		name := Safe(s.Log)
		if name == "" {
			name = "unknown log"
		}
		_, _ = fmt.Fprintf(w, "    %s  %s (%s)  %s  %s\n", s.Timestamp.Format("2006-01-02 15:04:05 MST"), Safe(s.LogID), name, s.Source, status)
	}
}
